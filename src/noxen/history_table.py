"""History's row-oriented view. Only on-screen cells become Rich renderables.

The caller owns capture, filtering, sorting and persistence. This widget receives
the ordered result and keeps selection by event ID. It uses public Textual APIs;
there is deliberately no cache of rendered events to invalidate after edits.
"""
from dataclasses import dataclass

from rich.cells import cell_len
from rich.style import Style
from rich.text import Text
from textual import events
from textual.binding import Binding
from textual.geometry import Size
from textual.message import Message
from textual.scroll_view import ScrollView
from textual.strip import Strip

from noxen.rendering import history_row_texts, history_row_values
from noxen.ui_theme import semantic_colors


def _cell_text(value) -> Text:
    # Intent fields are literal data, never Rich markup or terminal commands.
    text = value.copy() if isinstance(value, Text) else Text(str(value))
    text = text.split("\n", allow_blank=True)[0]
    text.expand_tabs(8)
    return text


def _cell_width(value: str) -> int:
    # Printable Unicode uses Rich's cell widths without creating renderables.
    # Tabs and control characters follow the visible cell's conversion.
    first = value.partition("\n")[0]
    if not first:
        return 0
    if first.isprintable():
        return len(first) if first.isascii() else cell_len(first)
    return _cell_text(value).cell_len


@dataclass
class HistoryColumn:
    label: str
    width: int | None = None
    content_width: int = 0

    @property
    def render_width(self) -> int:
        return (self.content_width if self.width is None else self.width) + 2


class HistoryTable(ScrollView, can_focus=True):
    ALLOW_SELECT = False
    BINDINGS = [
        Binding("up", "cursor_up", show=False), Binding("down", "cursor_down", show=False),
        Binding("left", "scroll_left", show=False), Binding("right", "scroll_right", show=False),
        Binding("pageup", "page_up", show=False), Binding("pagedown", "page_down", show=False),
        Binding("ctrl+home", "first", show=False), Binding("ctrl+end", "last", show=False),
        Binding("home", "horizontal_home", show=False), Binding("end", "horizontal_end", show=False),
    ]
    COMPONENT_CLASSES = {"history-table--header", "history-table--header-hover",
                         "history-table--cursor", "history-table--hover"}
    DEFAULT_CSS = """
    HistoryTable {
        background: $surface;
        color: $foreground;
        &:focus { background-tint: $foreground 5%; }
        & > .history-table--header {
            background: $panel;
            color: $foreground;
            text-style: bold;
        }
        &:focus > .history-table--header { background-tint: $foreground 5%; }
        & > .history-table--header-hover { background: $primary-muted; }
        & > .history-table--cursor {
            background: $primary;
            color: $button-color-foreground;
            text-style: $block-cursor-blurred-text-style;
        }
        &:focus > .history-table--cursor {
            background: $block-cursor-background;
            color: $block-cursor-foreground;
            text-style: $block-cursor-text-style;
        }
        & > .history-table--hover { background: $block-hover-background; }
    }
    """

    class RowHighlighted(Message):
        def __init__(self, table: "HistoryTable", entry_id: int | None):
            self.table, self.entry_id = table, entry_id
            super().__init__()

        @property
        def control(self):
            return self.table

    class HeaderSelected(Message):
        def __init__(self, table: "HistoryTable", column_key: str):
            self.table, self.column_key = table, column_key
            super().__init__()

        @property
        def control(self):
            return self.table

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.columns: dict[str, HistoryColumn] = {}
        self._entries: list[dict] = []
        self._positions: dict[int, int] = {}
        self.selected_id: int | None = None
        self._hover_id: int | None = None
        self._hover_header: str | None = None

    @property
    def row_count(self) -> int:
        return len(self._entries)

    @property
    def cursor_row(self) -> int:
        return self._positions.get(self.selected_id, 0)

    def entry_at(self, row: int) -> dict:
        return self._entries[row]

    def get_row_index(self, entry_id: int) -> int:
        return self._positions[entry_id]

    def configure_columns(self, columns: list[tuple[str, str, int | None]]) -> None:
        self.columns = {key: HistoryColumn(label, width) for key, label, width in columns}

    def set_entries(self, entries: list[dict], *, notify: bool = True) -> None:
        """Replace the result view, not the underlying captured events."""
        old_row = self.cursor_row
        old_scroll = int(self.scroll_y)
        old_top_id = self._entries[old_scroll]["id"] if 0 <= old_scroll < self.row_count else None
        was_visible = self.selected_id is not None and old_scroll <= old_row < old_scroll + self._page_height()
        old_id = self.selected_id
        self._entries = list(entries)
        self._positions = {entry["id"]: i for i, entry in enumerate(self._entries)}
        self.selected_id = (old_id if old_id in self._positions else entries[0]["id"]) if entries and self.columns else None
        self._hover_id = self._hover_header = None

        # Measure plain values across the WHOLE result so off-screen long values
        # cannot cause columns to jump while scrolling. No per-event width cache.
        automatic = [(key, column) for key, column in self.columns.items() if column.width is None]
        for column in self.columns.values():
            column.content_width = _cell_width(column.label)
        if automatic:
            for entry in self._entries:
                values = history_row_texts(entry)
                for key, column in automatic:
                    column.content_width = max(column.content_width, _cell_width(values[key]))
        self.virtual_size = Size(sum(c.render_width for c in self.columns.values()),
                                 self.row_count + bool(self.columns))
        if old_id == self.selected_id and was_visible:
            target = self.cursor_row - (old_row - old_scroll)
        elif old_id != self.selected_id:
            target = 0
        else:
            target = self._positions.get(old_top_id, old_scroll)
        self.scroll_to(y=max(0, target), animate=False, force=True)
        self.refresh()
        if notify:
            self.post_message(self.RowHighlighted(self, self.selected_id))

    def clear(self) -> None:
        self.set_entries([])

    def _page_height(self) -> int:
        return max(1, self.scrollable_content_region.height - bool(self.columns))

    def move_cursor(self, *, row: int, scroll: bool = True, animate: bool = False) -> None:
        self._hover_id = self._hover_header = None
        if not self._entries or not self.columns:
            return
        row = max(0, min(row, self.row_count - 1))
        self.selected_id = self._entries[row]["id"]
        if scroll:
            if row < self.scroll_y:
                self.scroll_to(y=row, animate=animate, force=True)
            elif row >= self.scroll_y + self._page_height():
                self.scroll_to(y=row - self._page_height() + 1, animate=animate, force=True)
        self.refresh()
        self.post_message(self.RowHighlighted(self, self.selected_id))

    def render_line(self, y: int) -> Strip:
        base = self.rich_style
        if not self.columns:
            return Strip.blank(self.size.width, base)
        header = y == 0
        row = int(self.scroll_y) + y - 1
        if not header and not 0 <= row < self.row_count:
            return Strip.blank(self.size.width, base)
        if header:
            values = [column.label for column in self.columns.values()]
            base += self.get_component_rich_style("history-table--header")
            identity = None
        else:
            entry = self._entries[row]
            identity = entry["id"]
            base += Style(meta={"history_id": identity})
            colors = semantic_colors(self.app.current_theme.dark)
            values = history_row_values(entry, set(self.columns),
                                        [(key, c.label) for key, c in self.columns.items()], colors.success, colors.error)
            if identity == self.selected_id:
                base += self.get_component_rich_style("history-table--cursor")
            elif identity == self._hover_id:
                base += self.get_component_rich_style("history-table--hover")
        pieces = []
        left, right = int(self.scroll_x), int(self.scroll_x) + self.size.width
        offset = 0
        for (key, column), value in zip(self.columns.items(), values):
            end = offset + column.render_width
            if end <= left:
                offset = end
                continue
            if offset >= right:
                break
            style = base
            if header and key == self._hover_header:
                style += self.get_component_rich_style("history-table--header-hover")
            style += Style(meta={"history_column": key, "history_id": identity, "history_header": header})
            cell = _cell_text(value)
            cell.truncate(column.render_width - 2, overflow="crop")
            # Style from payload values must not override the selection contrast.
            if not header and identity == self.selected_id:
                cell.stylize(base)
            text = Text(" ", style=style, no_wrap=True, end="")
            text.append_text(cell)
            # Extend only the on-screen slice, never pad an enormous off-screen
            # column to its full width for every visible row.
            strip = Strip(text.render(self.app.console)).apply_style(style)
            pieces.append(strip.crop_extend(max(0, left - offset), min(end, right) - offset, style))
            offset = end
        return Strip.join(pieces).crop_extend(0, self.size.width, base).apply_style(base)

    def on_mouse_move(self, event: events.MouseMove) -> None:
        meta = event.style.meta
        identity = meta.get("history_id")
        header = meta.get("history_column") if meta.get("history_header") else None
        if (identity, header) != (self._hover_id, self._hover_header):
            self._hover_id, self._hover_header = identity, header
            self.refresh()

    def on_leave(self, event: events.Leave) -> None:
        self._hover_id = self._hover_header = None
        self.refresh()

    def on_click(self, event: events.Click) -> None:
        meta = event.style.meta
        key = meta.get("history_column")
        identity = meta.get("history_id")
        if meta.get("history_header") and key in self.columns:
            self.post_message(self.HeaderSelected(self, key))
            event.stop()
        elif identity in self._positions:
            self.move_cursor(row=self._positions[identity])
            event.stop()

    def action_cursor_up(self) -> None:
        self.move_cursor(row=self.cursor_row - 1)

    def action_cursor_down(self) -> None:
        self.move_cursor(row=self.cursor_row + 1)

    def action_page_up(self) -> None:
        self.scroll_relative(y=-self._page_height(), animate=False)
        self.move_cursor(row=self.cursor_row - self._page_height(), scroll=False)

    def action_page_down(self) -> None:
        self.scroll_relative(y=self._page_height(), animate=False)
        self.move_cursor(row=self.cursor_row + self._page_height(), scroll=False)

    def action_first(self) -> None:
        self.move_cursor(row=0)

    def action_last(self) -> None:
        self.move_cursor(row=self.row_count - 1)

    def action_horizontal_home(self) -> None:
        self._hover_id = self._hover_header = None
        self.scroll_to(x=0, animate=False)

    def action_horizontal_end(self) -> None:
        self._hover_id = self._hover_header = None
        self.scroll_to(x=self.max_scroll_x, animate=False)

    def action_scroll_left(self) -> None:
        self._hover_id = self._hover_header = None
        super().action_scroll_left()

    def action_scroll_right(self) -> None:
        self._hover_id = self._hover_header = None
        super().action_scroll_right()
