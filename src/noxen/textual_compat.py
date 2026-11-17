from rich.segment import Segment, Segments
from rich.style import Style
from textual.color import Color
from textual.scrollbar import ScrollBar, ScrollBarRender
from textual.widgets import Select


SELECT_EMPTY = getattr(Select, "NULL", getattr(Select, "BLANK"))


def is_select_empty(value) -> bool:
    return value is SELECT_EMPTY


def set_button_label(button, label) -> None:
    """Change a button's label and its width with it: Textual only repaints a new label."""
    if str(button.label) != str(label):
        button.label = label
        button.refresh(layout=True)


class ThinScrollBarRender(ScrollBarRender):
    """Scrollbars drawn as lines, not filled cells: a heavy line for the thumb on a faint thin track.

    Click and drag work as with Textual's own scrollbars: the same mouse
    actions are attached to the same cells.
    """

    @classmethod
    def render_bar(cls, size=25, virtual_size=50, window_size=20, position=0, thickness=1,
                   vertical=True, back_color=Color.parse("#555555"), bar_color=Color.parse("#ff00ff")):
        size = int(size)
        track, thumb = ("│", "┃") if vertical else ("─", "━")
        width = thickness if vertical else 1
        # Textual passes Rich colors here; its own Color is needed to blend.
        back_color, bar_color = (c if isinstance(c, Color) else Color.from_rich_color(c) for c in (back_color, bar_color))
        back = Style(bgcolor=back_color.rich_color)
        rail = back + Style(color=back_color.blend(bar_color, 0.35).rich_color)
        if window_size and size and virtual_size and size != virtual_size:
            thumb_size = max(1, round(window_size * size / virtual_size))
            start = round((size - thumb_size) * position / (virtual_size - window_size))
            start = max(0, min(size - thumb_size, start))
            end = start + thumb_size
            segments = ([Segment(track * width, rail + Style(meta={"@mouse.down": "scroll_up"}))] * start
                        + [Segment(thumb * width, back + Style(color=bar_color.rich_color, meta={"@mouse.down": "grab"}))]
                        * thumb_size
                        + [Segment(track * width, rail + Style(meta={"@mouse.down": "scroll_down"}))] * (size - end))
        else:
            segments = [Segment(track * width, rail)] * size
        if vertical:
            return Segments(segments, new_lines=True)
        return Segments((segments + [Segment.line()]) * thickness, new_lines=False)


def use_thin_scrollbars() -> None:
    ScrollBar.renderer = ThinScrollBarRender
