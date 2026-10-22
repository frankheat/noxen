import copy
from types import SimpleNamespace

from rich.cells import cell_len
from textual.widgets import Input, Select

from noxen.app import NoxenApp
from noxen.intent_mods import EXTRA_TYPE_OPTIONS
from tests.ui_test_case import IsolatedAppTestCase


class EditorTypeWidthTests(IsolatedAppTestCase):
    async def test_compact_type_column_and_full_dropdown_at_supported_widths(self):
        app = NoxenApp(SimpleNamespace(project=None,
            new_project=str(self.settings_path.parent / "width.noxen"), skip_device_scan=True))
        self.addCleanup(app.db.close)
        original = {"component": None, "action": "TEST", "categories": [], "flags": 0,
                    "extras": {
                        "existing": {"type": "java.lang.String", "value": "unchanged"},
                        "opaque": {"type": "example.VeryLongCustomTypeName", "value": "(opaque object)",
                                   "editable": False},
                        "long_" * 40: {"type": "java.lang.Integer", "value": "42"},
                    }}
        async with app.run_test(size=(120, 60)) as pilot:
            app.query_one("#main_tabs").active = "tab_intercept"
            app._current_intercepted_entry = {"id": 1, "intent": copy.deepcopy(original)}
            app._enter_edit_mode()
            app._add_edit_extra_row("", "string", "", is_new=True)
            await pilot.pause()
            selector = app.query_one(".ef_x_type_select", Select)
            current = selector.query_one("SelectCurrent")
            option_label = current.query_one("#label")
            overlay = selector.query_one("SelectOverlay")
            header = app.query_one(".ef_x_type_header")
            value_header = app.query_one(".ef_x_value_header")
            for theme in ("noxen-dark", "noxen-light"):
                app.theme = theme
                for width in (120, 80, 72, 60):
                    with self.subTest(theme=theme, width=width):
                        await pilot.resize_terminal(width, 60)
                        await pilot.pause()
                        self.assertEqual(selector.region.width, 16)
                        self.assertEqual(header.region.width, 16)
                        self.assertEqual(option_label.content_region.x, header.content_region.x)
                        for label in app.query(".ef_x_type_label"):
                            self.assertEqual(label.region.width, 16)
                            self.assertEqual(label.content_region.x, header.content_region.x)
                        for row in app.query(".ef_x_row"):
                            value = row.query_one("ExtraValueInput", Input)
                            self.assertEqual(value.content_region.x, value_header.content_region.x)
                            self.assertGreaterEqual(value.content_region.width, 9)
                            self.assertLessEqual(row.query_one(".ef_x_rm").region.right, row.content_region.right - 2)
                        selector.focus()
                        await pilot.press("enter")
                        await pilot.pause()
                        self.assertTrue(overlay.display)
                        self.assertLessEqual(overlay.region.right, width)
                        for index, (label, kind) in enumerate(EXTRA_TYPE_OPTIONS):
                            selector.value = kind
                            overlay.highlighted = index
                            overlay.scroll_to_highlight()
                            await pilot.pause()
                            self.assertGreaterEqual(option_label.content_region.width, cell_len(label))
                            lines = ["".join(segment.text for segment in overlay.render_line(y))
                                     for y in range(overlay.content_region.height)]
                            self.assertTrue(any(label in line for line in lines), (label, lines))
                        await pilot.press("escape")
                        await pilot.pause()
                        self.assertFalse(overlay.display)
                        self.assertEqual(app._collect_edit_mods(), [])
                        self.assertEqual(app._current_intercepted_entry["intent"], original)
