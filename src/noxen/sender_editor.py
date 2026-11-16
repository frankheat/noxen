"""Structured Sender drafts. Widgets collect values; Sender validation remains authoritative."""

import copy
from contextlib import contextmanager
import re

from rich.text import Text
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Collapsible, Input, Label, Select, TextArea

from noxen.extra_value_input import ExtraValueInput, extra_value_preview, needs_value_preview
from noxen.modals import ModalButton
from noxen.textual_compat import is_select_empty

MISSING = object()
SCALARS = ("String", "boolean", "byte", "short", "int", "long", "float", "double", "char", "Uri")
TYPES = (*SCALARS, "Bundle", "Intent", *(kind + "[]" for kind in SCALARS if kind != "Uri"), "Intent[]")
CONTENT_TYPES = ("String", "boolean", "byte", "short", "int", "long", "float", "double", "byte[]")
LABELS = {"mimeType": "MIME type", "data": "Data URI", "receiverPermission": "Receiver perm",
          "uri": "URI", "sortOrder": "Sort order", "selectionArgs": "Selection args",
          "maxRows": "Max rows", "maxBytes": "Max bytes", "clipData": "ClipData",
          "mimeTypes": "MIME types", "htmlText": "HTML text"}


@contextmanager
def changing_draft(widget):
    widget._changing_draft = True
    try:
        yield
    finally:
        widget._changing_draft = False


def structure_changed(widget):
    """Let the request editor place new or removed objects before the next frame."""
    refresh = getattr(widget.screen, "refresh_navigation", None)
    if refresh is not None:
        refresh()


def check_draft_ready(widget):
    if getattr(widget, "_changing_draft", False):
        raise ValueError("The editor is updating. Try again when the fields are ready.")


def text_preview(value):
    if value is MISSING:
        return ""
    if value is None:
        return ""
    if value == "":
        return ""
    return extra_value_preview(value) if needs_value_preview(value) else value


def escaped_text(value):
    """Only escape characters the text editor cannot safely display literally."""
    return "".join("\\\\" if c == "\\" else
                   "\\n" if c == "\n" else "\\r" if c == "\r" else "\\t" if c == "\t" else
                   f"\\u{ord(c):04x}" if needs_value_preview(c) else c for c in value)


def unescape_text(value):
    result, index = [], 0
    short = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "\\": "\\"}
    while index < len(value):
        char = value[index]
        index += 1
        if char != "\\":
            result.append(char)
            continue
        if index == len(value):
            raise ValueError("Use \\\\ for a literal backslash")
        code = value[index]
        index += 1
        if code in short:
            result.append(short[code])
        elif code == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", value[index:index + 4]):
            result.append(chr(int(value[index:index + 4], 16)))
            index += 4
        else:
            raise ValueError("Use \\n, \\r, \\t, \\u0000 or \\\\ for escaped characters")
    text = "".join(result)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Unpaired UTF-16 surrogates are not supported") from None
    return text


class SenderTextModal(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Cancel")]
    DEFAULT_CSS = """
    SenderTextModal { align: center middle; }
    SenderTextModal > Vertical { width: 90%; max-width: 80; height: 20; max-height: 95%;
        padding: 1 2; border: solid $foreground-muted; background: $surface; }
    SenderTextModal .title { text-style: bold; margin-bottom: 1; }
    SenderTextModal Select { height: 3; }
    SenderTextModal TextArea { height: 1fr; min-height: 3; }
    SenderTextModal .text_hint { width: 1fr; height: auto; color: $foreground-muted; }
    SenderTextModal .buttons { height: 3; align: right middle; margin-top: 1; }
    SenderTextModal Button { width: auto; min-width: 0; margin-left: 1; }
    """

    def __init__(self, title, value, *, nullable=False, optional=False):
        super().__init__()
        self.caption, self.value = title, value
        self.nullable, self.optional = nullable, optional

    def compose(self):
        choices = [("Text", "text")]
        if self.optional:
            choices.append(("Not set", "absent"))
        if self.nullable:
            choices.append(("Null", "null"))
        mode = "absent" if self.value is MISSING else "null" if self.value is None else "text"
        with Vertical():
            yield Label(Text(self.caption), classes="title")
            yield Select(choices, value=mode, allow_blank=False, id="sender_text_state")
            yield TextArea(escaped_text(self.value) if isinstance(self.value, str) else "", id="sender_text_value")
            yield Label(r"Text without quotes. Escapes: \n newline · \t tab · \u0000 NUL · \\ backslash", classes="text_hint")
            with Horizontal(classes="buttons"):
                yield ModalButton("Cancel", id="sender_text_cancel")
                yield ModalButton("Apply", id="sender_text_apply")

    def on_mount(self):
        self.update_mode()

    def update_mode(self):
        self.query_one(TextArea).disabled = self.query_one(Select).value != "text"

    def on_select_changed(self, event):
        event.stop()
        self.update_mode()

    def on_button_pressed(self, event):
        event.stop()
        if event.button.id == "sender_text_cancel":
            self.dismiss(None)
            return
        mode = self.query_one(Select).value
        try:
            value = MISSING if mode == "absent" else None if mode == "null" else unescape_text(self.query_one(TextArea).text)
        except ValueError as error:
            self.notify(str(error), severity="error")
            return
        self.dismiss((value,))


class ScalarField(Horizontal):
    DEFAULT_CSS = """
    ScalarField { height: 3; align: left middle; }
    ScalarField > Label { width: 16; height: 3; content-align: left middle; color: $foreground-muted; }
    ScalarField Input { width: 1fr; height: 3; border: none; padding: 1 0; margin: 0; }
    ScalarField Select { width: 1fr; height: 3; margin: 0; }
    ScalarField Button { width: 8; min-width: 8; height: 3; margin-left: 1; }
    """

    def __init__(self, key, kind, value=MISSING, *, optional=False, nullable=False, label=None, input_id=None):
        super().__init__()
        self.key, self.kind, self.original = key, kind, value
        self.optional, self.nullable = optional, nullable
        self.caption, self.input_id = label or LABELS.get(key, key.capitalize()), input_id
        self.text = kind in ("String", "char", "Uri")

    def compose(self):
        yield Label(Text(self.caption))
        if self.kind == "boolean":
            yield Select([("False", False), ("True", True)], value=bool(self.original) if self.original is not MISSING else False,
                         allow_blank=False)
        else:
            self.initial_text = text_preview(self.original) if self.text else (
                "" if self.original is MISSING else str(self.original))
            yield ExtraValueInput(self.initial_text, select_on_focus=False, id=self.input_id,
                                  placeholder="Not set" if self.original is MISSING else "Null" if self.original is None else "Empty string" if self.original == "" else "",
                                  disabled=self.text and isinstance(self.original, str) and needs_value_preview(self.original))
            if self.text:
                yield ModalButton("⋯", classes="scalar_edit", tooltip="Value options")

    def collect(self):
        check_draft_ready(self)
        if self.kind == "boolean":
            return self.query_one(Select).value
        control = self.query_one(Input)
        if control.value == self.initial_text:
            return self.original
        if self.text:
            return MISSING if self.optional and control.value == "" else control.value
        try:
            if self.optional and control.value == "":
                return MISSING
            if self.kind == "long":
                return str(int(control.value, 10))
            if self.kind in ("float", "double"):
                return float(control.value)
            return int(control.value, 0) if self.kind == "flags" else int(control.value, 10)
        except ValueError:
            raise ValueError(f"{self.caption}: enter a valid {self.kind}") from None

    def apply_text(self, result):
        if result is None:
            return
        self.original = result[0]
        field = self.query_one(Input)
        self.initial_text = text_preview(self.original)
        field.value = self.initial_text
        field.placeholder = "Not set" if self.original is MISSING else "Null" if self.original is None else "Empty string" if self.original == "" else ""
        field.disabled = isinstance(self.original, str) and needs_value_preview(self.original)

    def on_button_pressed(self, event):
        event.stop()
        self.app.push_screen(SenderTextModal(self.caption, self.collect(), nullable=self.nullable, optional=self.optional), self.apply_text)


def default_value(kind):
    if kind.endswith("[]") or kind == "items":
        return []
    if kind in ("Intent", "Bundle", "ContentValues", "ClipData", "Item"):
        return {}
    if kind == "boolean":
        return False
    if kind == "long":
        return "0"
    return "" if kind in ("String", "char", "Uri") else 0


def object_fields(kind):
    if kind == "Intent":
        return [(key, "flags" if key == "flags" else "String", True, key != "flags") for key in
                ("component", "package", "action", "data", "mimeType", "flags")]
    if kind == "ClipData":
        return [("label", "String", True, True)]
    return [(key, "String", True, True) for key in ("text", "htmlText", "uri")]


def object_sections(kind):
    if kind == "Intent":
        return [("categories", "String[]"), ("extras", "Bundle"), ("selector", "Intent"), ("clipData", "ClipData")]
    if kind == "ClipData":
        return [("mimeTypes", "String[]"), ("items", "items")]
    return [("intent", "Intent")]


class ValueEditor(Vertical):
    DEFAULT_CSS = """
    ValueEditor { height: auto; }
    ValueEditor .entries { height: auto; }
    ValueEditor .add_row { height: 3; align: right middle; }
    ValueEditor .add_row > .add_title { width: 1fr; height: 3; content-align: left middle; text-style: bold; }
    ValueEditor Button { width: auto; min-width: 0; }
    ValueEditor .entry { height: auto; margin-bottom: 1; }
    ValueEditor .entry_header { height: 3; align: left middle; }
    ValueEditor .entry_header > ScalarField { width: 2fr; }
    ValueEditor .entry_header > ScalarField > Label { display: none; }
    ValueEditor .entry_header > Select { width: 14; margin: 0 3 0 1; }
    ValueEditor .entry_preview { width: 3fr; height: auto; }
    ValueEditor .entry_preview ScalarField > Label { display: none; }
    ValueEditor .entry_header > Label { width: 1fr; height: 3; content-align: left middle; }
    ValueEditor .column_headings { height: 1; color: $foreground-muted; }
    ValueEditor .column_headings > Label { width: 2fr; }
    ValueEditor .column_headings > .type_heading { width: 14; margin: 0 3 0 1; }
    ValueEditor .column_headings > .value_heading { width: 3fr; }
    ValueEditor .column_headings > .remove_heading { width: 8; }
    ValueEditor .entry_header > Button { width: 8; }
    ValueEditor .entry_body { height: auto; padding-left: 2; }
    ValueEditor .null_row { height: 3; align: left middle; }
    ValueEditor .null_row > Label { width: 1fr; }
    """

    def __init__(self, kind, value, *, depth=0, show_add=True):
        super().__init__()
        self.kind, self.value, self.depth = kind, copy.deepcopy(value), depth
        self.show_add = show_add
        self.members = []

    def on_resize(self, event):
        self.set_class(event.size.width < 60, "narrow")

    def compose(self):
        if self.kind in SCALARS:
            field = ScalarField("value", self.kind, self.value, nullable=self.kind in ("String", "Uri"))
            self.members = [field]
            yield field
        elif self.kind in ("Intent", "ClipData", "Item"):
            for key, kind, optional, nullable in object_fields(self.kind):
                field = ScalarField(key, kind, self.value.get(key, MISSING), optional=optional, nullable=nullable)
                self.members.append(field)
                yield field
            for key, kind in object_sections(self.kind):
                depth = self.depth + (1 if key in ("selector", "intent") else 0)
                section = OptionalSection(key, kind, self.value.get(key, MISSING), depth=depth)
                self.members.append(section)
                yield section
        else:
            is_map = self.kind in ("Bundle", "ContentValues")
            if self.show_add:
                with Horizontal(classes="add_row"):
                    yield Label("", classes="add_title")
                    yield ModalButton("+ Add", classes="add_entry")
            if is_map:
                yield Horizontal(Label("Key"), Label("Type", classes="type_heading"),
                                 Label("Value", classes="value_heading"), Label("", classes="remove_heading"),
                                 classes="column_headings")
            with Vertical(classes="entries"):
                for key, value in (self.value.items() if is_map else enumerate(self.value)):
                    row = EntryRow(self, key, value)
                    self.members.append(row)
                    yield row

    def collect(self):
        check_draft_ready(self)
        if self.kind in SCALARS:
            return self.members[0].collect()
        if self.kind in ("Intent", "ClipData", "Item"):
            result = {}
            for field in self.members:
                value = field.collect()
                if value is not MISSING:
                    result[field.key] = value
            return result
        if self.kind in ("Bundle", "ContentValues"):
            result = {}
            for row in self.members:
                key = row.key_field.collect()
                if key in result:
                    raise ValueError(f"Duplicate key: {key!r}")
                result[key] = {"type": row.kind, "value": row.collect()}
            return result
        return [row.collect() for row in self.members]

    async def on_button_pressed(self, event):
        if not event.button.has_class("add_entry"):
            return
        event.stop()
        await self.add_entry()

    async def add_entry(self):
        if self.depth > 8:
            self.notify("Nesting exceeds 8 levels", severity="error")
            return
        is_map = self.kind in ("Bundle", "ContentValues")
        value = {"type": "String", "value": ""} if is_map else default_value("Item" if self.kind == "items" else self.kind[:-2])
        row = EntryRow(self, "" if is_map else len(self.members), value)
        with changing_draft(self):
            await self.query_one(".entries", Vertical).mount(row)
            self.members.append(row)
        structure_changed(self)
        row.scroll_visible()


class EntryRow(Vertical):
    def __init__(self, owner, key, value):
        self.is_map = owner.kind in ("Bundle", "ContentValues")
        super().__init__(classes="entry map_entry" if self.is_map else "entry")
        self.owner, self.key = owner, key
        self.kind = value["type"] if self.is_map else "Item" if owner.kind == "items" else owner.kind[:-2]
        self.value = copy.deepcopy(value["value"] if self.is_map else value)
        self.editor = None
        self.drafts = {}
        # Start in the owner's layout; the first resize would otherwise redraw the row.
        self.set_class(owner.has_class("narrow"), "narrow")

    def on_resize(self, event):
        self.set_class(event.size.width < 60, "narrow")

    def compose(self):
        preview, body = self.value_widgets()
        with Horizontal(classes="entry_header"):
            if self.is_map:
                self.key_field = ScalarField("key", "String", self.key)
                yield self.key_field
                kinds = CONTENT_TYPES if self.owner.kind == "ContentValues" else TYPES
                yield Select([(kind, kind) for kind in kinds], value=self.kind, allow_blank=False)
            else:
                yield Label(f"Item {self.key}")
            yield Vertical(*preview, classes="entry_preview")
            yield ModalButton("[×]", classes="remove_entry")
        yield Vertical(*body, classes="entry_body")

    def value_widgets(self):
        if self.value is None and self.kind not in SCALARS:
            self.editor = None
            return [ModalButton("Null · Set", classes="set_value", tooltip="Create a value instead of null")], []
        self.editor = ValueEditor(self.kind, self.value, depth=self.owner.depth + (0 if self.owner.kind == "items" else 1))
        if self.kind in SCALARS:
            return [self.editor], []
        body = [Collapsible(self.editor, title=self.kind, collapsed=False)]
        if self.kind != "Item":
            body.append(ModalButton("Set null", classes="set_null"))
        return [ModalButton("Open", classes="open_value")], body

    def collect(self):
        check_draft_ready(self)
        return self.editor.collect() if self.editor is not None else None

    async def rebuild(self):
        with self.app.batch_update():  # Swap the value in one repaint.
            with changing_draft(self):
                preview = self.query_one(".entry_preview", Vertical)
                body = self.query_one(".entry_body", Vertical)
                await preview.remove_children()
                await body.remove_children()
                preview_widgets, body_widgets = self.value_widgets()
                await preview.mount(*preview_widgets)
                await body.mount(*body_widgets)
            structure_changed(self)

    async def on_select_changed(self, event):
        if event.select.parent is not self.query_one(".entry_header") or is_select_empty(event.value):
            return
        event.stop()
        if event.value == self.kind:
            return
        try:
            self.drafts[self.kind] = self.collect()
        except ValueError as error:
            with event.select.prevent(Select.Changed):
                event.select.value = self.kind
            self.notify(str(error), severity="error")
            return
        self.kind = event.value
        self.value = copy.deepcopy(self.drafts.get(self.kind, default_value(self.kind)))
        await self.rebuild()

    async def on_button_pressed(self, event):
        event.stop()
        if event.button.has_class("open_value"):
            self.screen.focus_request_object(self.editor)
        elif event.button.has_class("remove_entry"):
            self.owner.members.remove(self)
            owner = self.owner
            await self.remove()
            if not self.is_map:
                for index, row in enumerate(owner.members):
                    row.key = index
                    row.query_one(".entry_header > Label", Label).update(f"Item {index}")
            structure_changed(owner)
        elif event.button.has_class("set_null"):
            try:
                self.drafts[self.kind] = self.collect()
            except ValueError as error:
                self.notify(str(error), severity="error")
                return
            self.value = None
            await self.rebuild()
        elif event.button.has_class("set_value"):
            self.value = copy.deepcopy(self.drafts.get(self.kind, default_value(self.kind)))
            await self.rebuild()


class OptionalSection(Vertical):
    DEFAULT_CSS = """
    OptionalSection { height: auto; border-top: solid $foreground-muted; margin-top: 1; }
    OptionalSection > .section_header { height: 3; align: left middle; }
    OptionalSection > .section_header > Label { width: 1fr; height: 3; content-align: left middle; text-style: bold; }
    OptionalSection > .section_header > Button { width: auto; min-width: 0; margin-left: 1; }
    OptionalSection > .section_body { height: auto; }
    OptionalSection Collapsible { background: transparent; padding: 0; border: none; }
    """

    def __init__(self, key, kind, value=MISSING, *, depth=0, required=False):
        super().__init__()
        self.key, self.kind, self.initial = key, kind, value
        self.depth, self.required = depth, required
        self.collection = kind.endswith("[]") or kind in ("Bundle", "ContentValues", "items")
        self.editor = None

    def compose(self):
        present = self.initial is not MISSING and self.initial is not None
        with Horizontal(classes="section_header"):
            yield Label(LABELS.get(self.key, self.key.capitalize()))
            add = ModalButton("+ Add", classes="section_add_entry")
            add.display = present and self.collection
            yield add
            yield ModalButton("Remove" if present else "+ Add", classes="section_toggle", disabled=self.required and present)
        with Vertical(classes="section_body"):
            if present:
                self.editor = ValueEditor(self.kind, self.initial, depth=self.depth, show_add=False)
                yield self.editor

    def collect(self):
        check_draft_ready(self)
        return self.editor.collect() if self.editor is not None else self.initial

    async def on_button_pressed(self, event):
        if event.button.has_class("section_add_entry"):
            event.stop()
            await self.editor.add_entry()
            return
        if not event.button.has_class("section_toggle"):
            return
        event.stop()
        if self.editor is None and self.depth > 8:
            self.notify("Nesting exceeds 8 levels", severity="error")
            return
        with changing_draft(self):
            body = self.query_one(".section_body", Vertical)
            if self.editor is not None:
                await body.remove_children()
                self.editor = None
                self.initial = MISSING
                event.button.label = "+ Add"
                self.query_one(".section_add_entry", Button).display = False
            else:
                self.editor = ValueEditor(self.kind, default_value(self.kind), depth=self.depth, show_add=False)
                await body.mount(self.editor)
                event.button.label = "Remove"
                event.button.disabled = self.required
                self.query_one(".section_add_entry", Button).display = self.collection
                if self.collection:
                    await self.editor.add_entry()
        # The label is not a layout reactive: without this the button keeps its old width.
        event.button.refresh(layout=True)
        structure_changed(self)
