"""A JSON editor for Sender requests: colours, auto-pairing, completion and folding."""

from rich.style import Style
from rich.text import Text
from textual import events
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Label, OptionList, TextArea
from textual.widgets.option_list import Option
from textual.widgets.text_area import Selection, TextAreaTheme

from noxen import sender_json

PAIRS = {"{": "}", "[": "]", '"': '"'}
PALETTES = {
    True: {"key": "#7fd6c2", "string": "#e7be42", "number": "#c9a0ff", "constant": "#ff9d7a",
           "punct": "#8a918e", "fold": "#0e1412 on #7fd6c2", "word": "#e8efec"},
    False: {"key": "#00756a", "string": "#8a5a00", "number": "#6b3fb3", "constant": "#b5411b",
            "punct": "#6d7471", "fold": "#ffffff on #00756a", "word": "#1c2321"},
}


def json_text(text, dark=True):
    """Read-only JSON in the editor's colours, for panels that only show it."""
    result = Text(text)
    for kind, start, end, _ in sender_json.tokens(text):
        result.stylize(PALETTES[dark][kind], start, end)
    return result


class CompletionList(OptionList):
    """Suggestions under the cursor. The editor keeps the focus and drives the highlight."""

    can_focus = False


class JsonArea(TextArea):
    BINDINGS = [
        Binding("ctrl+@", "suggest", "Suggest", show=False, priority=True),
        Binding("ctrl+space", "suggest", "Suggest", priority=True),
        Binding("ctrl+o", "fold", "Fold", priority=True),
        Binding("ctrl+n", "unfold_all", "Unfold all", priority=True),
    ]

    def __init__(self, root="request", escape_leaves=True, **kwargs):
        super().__init__("", soft_wrap=False, show_line_numbers=True, tab_behavior="indent", **kwargs)
        self.root = root  # What the document is: a Sender "request", or an "intent".
        # Escape moves focus out of the editor, or is left to the app (Intercept cancels the edit with it).
        self.escape_leaves = escape_leaves
        self.indent_width = 4
        self.folds = {}
        self._found = None
        self._matches = []

    def on_mount(self):
        for dark, colours in PALETTES.items():
            self.register_theme(TextAreaTheme(
                name=f"noxen_json_{'dark' if dark else 'light'}",
                syntax_styles={"json." + name: Style.parse(colour) for name, colour in colours.items()}))
        self.use_palette()
        self.watch(self.app, "theme", lambda *_: self.use_palette(), init=False)

    def use_palette(self):
        self.theme = "noxen_json_light" if "light" in str(self.app.theme) else "noxen_json_dark"

    def _build_highlight_map(self):
        """Colour JSON without a grammar package: the tokens come from `sender_json`."""
        self._line_cache.clear()
        self._highlights.clear()
        for line, spans in sender_json.highlights(self.text).items():
            self._highlights[line].extend(spans)

    # ------------------------------------------------------------ text

    def load(self, text, folds=None):
        self.folds = dict(folds or {})
        self.load_text(text)
        self.close_completions()

    def full_text(self):
        return sender_json.expand(self.text, self.folds)

    def offset(self):
        row, column = self.cursor_location
        return sum(len(line) + 1 for line in self.text.split("\n")[:row]) + column

    def location(self, offset):
        before = self.text[:offset]
        return before.count("\n"), len(before) - (before.rfind("\n") + 1)

    def set_text(self, text, offset):
        """Replace the document as one undoable edit and put the cursor at `offset`."""
        self.replace(text, (0, 0), self.document.end)
        self.move_cursor(self.location(offset))

    # ------------------------------------------------------------ completion

    @property
    def popup(self):
        return self.parent.query_one(CompletionList)

    def close_completions(self):
        self._matches = []
        if self.parent is not None and self.parent.query(CompletionList):
            self.popup.display = False

    def show_completions(self, always=False):
        if self.read_only:
            return
        self._found, self._matches = sender_json.completions(self.text, self.offset(), always, self.root)
        popup = self.popup
        if not self._matches:
            popup.display = False
            return
        popup.clear_options()
        popup.add_options([Option(Text(label)) for label, _ in self._matches[:40]])
        popup.highlighted = 0
        width = min(40, max(len(label) for label, _ in self._matches) + 4)
        height = min(8, len(self._matches)) + 2
        origin = self.parent.region.offset
        cursor = self.cursor_screen_offset
        x = max(0, min(cursor.x - origin.x - len(self._found["prefix"]), self.parent.region.width - width))
        y = cursor.y - origin.y + 1
        if y + height > self.parent.region.height:  # No room below: open above the line.
            y = max(0, cursor.y - origin.y - height)
        popup.styles.width, popup.styles.height = width, height
        popup.styles.offset = (x, y)
        popup.display = True

    def accept_completion(self, index=None):
        popup = self.popup
        index = popup.highlighted if index is None else index
        if not self._matches or index is None:
            return
        text, offset, selected = sender_json.apply_completion(
            self.text, self.offset(), self._found, self._matches[index][1])
        self.close_completions()
        self.set_text(text, offset)
        if selected:
            self.selection = Selection(self.location(offset), self.location(offset + selected))
        # A snippet that ends inside a value may itself offer names (operation, type).
        self.call_after_refresh(self.show_completions, True if text[offset - 1:offset] == '"' and
                                self._value_has_choices() else False)

    def _value_has_choices(self):
        found, matches = sender_json.completions(self.text, self.offset(), True, self.root)
        return found["position"] == "value" and found["quoted"] and bool(matches)

    def action_suggest(self):
        self.show_completions(always=True)

    # ------------------------------------------------------------ folding

    def action_fold(self):
        result = sender_json.toggle_fold(self.text, self.offset(), self.folds)
        if result is not None:
            self.close_completions()
            self.set_text(*result)

    def action_unfold_all(self):
        offset = self.offset()
        self.set_text(self.full_text(), min(offset, len(self.full_text())))
        self.folds.clear()

    # ------------------------------------------------------------ keys

    async def _on_key(self, event: events.Key):
        if self.read_only:
            await super()._on_key(event)
            return
        popup_open = bool(self._matches) and self.popup.display
        if popup_open and event.key in ("down", "up", "tab", "enter", "escape"):
            event.stop()
            event.prevent_default()
            popup = self.popup
            if event.key == "escape":
                self.close_completions()
            elif event.key in ("tab", "enter"):
                self.accept_completion()
            else:
                step = 1 if event.key == "down" else -1
                popup.highlighted = (popup.highlighted + step) % popup.option_count
            return
        if event.key == "escape" and not self.escape_leaves:
            return  # Not handled here: the app's binding gets it.
        if self.selection.start == self.selection.end and self._edit_pair(event):
            event.stop()
            event.prevent_default()
        else:
            await super()._on_key(event)
        if event.is_printable or event.key == "backspace":
            self.call_after_refresh(self.show_completions)
        elif event.key not in ("shift", "ctrl"):
            self.close_completions()

    def _edit_pair(self, event):
        """Brackets and quotes come in pairs; Enter keeps the indentation and opens a block."""
        text, offset = self.text, self.offset()
        before, after = text[offset - 1:offset], text[offset:offset + 1]
        line_start = text.rfind("\n", 0, offset) + 1
        indent = text[line_start:offset]
        indent = indent[:len(indent) - len(indent.lstrip(" "))]
        char = event.character
        if char in ("}", "]", '"') and after == char and (char != '"' or before != "\\"):
            self.move_cursor(self.location(offset + 1))  # Type over the closer that is already there.
            return True
        if char == "{":
            inner = indent + sender_json.INDENT
            self.set_text(f"{text[:offset]}{{\n{inner}\n{indent}}}{text[offset:]}", offset + 2 + len(inner))
            return True
        if char in ("[", '"'):
            if char == '"' and (after.isalnum() or before.isalnum()):
                return False
            self.set_text(text[:offset] + char + PAIRS[char] + text[offset:], offset + 1)
            return True
        if event.key == "enter":
            inner = indent + (sender_json.INDENT if before in ("{", "[") else "")
            tail = f"\n{indent}" if before in ("{", "[") and after == PAIRS.get(before) else ""
            self.set_text(f"{text[:offset]}\n{inner}{tail}{text[offset:]}", offset + 1 + len(inner))
            return True
        if event.key == "backspace" and before in PAIRS and after == PAIRS[before]:
            self.set_text(text[:offset - 1] + text[offset + 1:], offset - 1)
            return True
        if event.key == "backspace" and before == " " and not text[line_start:offset].strip() and \
                (offset - line_start) % 4 == 0 and offset - line_start >= 4:
            self.set_text(text[:offset - 4] + text[offset:], offset - 4)  # One indentation level.
            return True
        return False

    def on_blur(self):
        self.close_completions()


class JsonRequestEditor(Vertical):
    """The editor with its suggestion list and a one-line status."""

    DEFAULT_CSS = """
    JsonRequestEditor { height: 1fr; }
    JsonRequestEditor > JsonArea { height: 1fr; border: none; padding: 0; background: $background; }
    JsonRequestEditor > CompletionList {
        position: absolute; overlay: screen; display: none;
        border: round $accent; background: $surface; padding: 0; scrollbar-size-vertical: 1;
    }
    JsonRequestEditor > CompletionList > .option-list--option-highlighted { background: $accent 35%; color: $foreground; text-style: bold; }
    JsonRequestEditor > .json_status { height: 1; color: $foreground-muted; }
    JsonRequestEditor > .json_status.error { color: $error; }
    """

    def __init__(self, root="request", escape_leaves=True, **kwargs):
        super().__init__(**kwargs)
        self.root, self.escape_leaves = root, escape_leaves

    def compose(self):
        yield JsonArea(root=self.root, escape_leaves=self.escape_leaves)
        yield CompletionList()
        yield Label("", classes="json_status", markup=False)

    @property
    def area(self):
        return self.query_one(JsonArea)

    def say(self, message, error=False):
        status = self.query_one(".json_status", Label)
        status.set_class(error, "error")
        status.update(Text(message))

    def on_option_list_option_selected(self, event):
        event.stop()
        self.area.accept_completion(event.option_index)
        self.area.focus()
