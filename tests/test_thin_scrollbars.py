import unittest

from rich.color import Color as RichColor
from textual.scrollbar import ScrollBar

from noxen.textual_compat import ThinScrollBarRender, use_thin_scrollbars


class ThinScrollBarTests(unittest.TestCase):
    def cells(self, **kwargs):
        bar = ThinScrollBarRender.render_bar(back_color=RichColor.parse("#000000"),
                                             bar_color=RichColor.parse("#ffffff"), **kwargs)
        return [segment for segment in bar.segments if segment.text != "\n"]

    def test_thumb_and_track_are_lines_that_keep_the_mouse_actions(self):
        cells = self.cells(size=10, virtual_size=40, window_size=20, position=20)
        self.assertEqual("".join(cell.text for cell in cells), "│││││┃┃┃┃┃")
        self.assertEqual([cell.style.meta["@mouse.down"] for cell in cells],
                         ["scroll_up"] * 5 + ["grab"] * 5)
        horizontal = self.cells(size=6, virtual_size=12, window_size=6, position=0, vertical=False)
        self.assertEqual("".join(cell.text for cell in horizontal), "━━━───")

    def test_without_anything_to_scroll_only_the_track_shows(self):
        self.assertEqual("".join(cell.text for cell in self.cells(size=4, virtual_size=4, window_size=4)), "││││")

    def test_the_app_uses_it(self):
        use_thin_scrollbars()
        self.assertIs(ScrollBar.renderer, ThinScrollBarRender)


if __name__ == "__main__":
    unittest.main()
