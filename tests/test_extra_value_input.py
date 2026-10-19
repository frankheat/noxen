import copy
import json
import unittest
from types import SimpleNamespace
from unittest.mock import PropertyMock, patch

from textual import events
from textual.widgets import Input, Select

from noxen.app import NoxenApp
from noxen.extra_value_input import ExtraValueInput, extra_value_preview, needs_value_preview
from tests.ui_test_case import IsolatedAppTestCase


UNSAFE_VALUES = (
    "first\nsecond", "first\r\nsecond", "mixed\r\nLF\nCR\rend", "\n",
    "a\tb", "a\x00b", "a\x1b[31mb", "a\x85b", "a\u2028b", "a\u2029b",
    "a\u202eb\u202c", "a\u2066b\u2069", "a\ud800b",
)
SAFE_VALUES = ("", "hello", '  "quoted"  ', r"C:\path\new", r"literal\ntext",
               "caffè 日本語 🙂 e\u0301 👩\u200d💻", '{"enabled": true}', "X" * 2048)


class ValuePreviewTests(unittest.TestCase):
    def test_preview_is_reversible_and_contains_no_unsafe_characters(self):
        for value in UNSAFE_VALUES:
            with self.subTest(value=repr(value)):
                self.assertTrue(needs_value_preview(value))
                preview = extra_value_preview(value)
                self.assertFalse(needs_value_preview(preview))
                self.assertEqual(json.loads(preview), value)

    def test_ordinary_values_do_not_need_a_preview(self):
        for value in SAFE_VALUES:
            self.assertFalse(needs_value_preview(value), repr(value))


class ExtraValueInputTests(IsolatedAppTestCase):
    def make_app(self):
        app = NoxenApp(SimpleNamespace(project=None,
            new_project=str(self.settings_path.parent / "values.noxen"), skip_device_scan=True))
        self.addCleanup(app.db.close)
        return app

    async def open_editor(self, app, pilot, extras):
        app.query_one("#main_tabs").active = "tab_intercept"
        original = {"component": None, "action": "ORIGINAL", "data": None,
                    "mimeType": None, "categories": [], "flags": 0, "extras": extras}
        app._current_intercepted_entry = {"id": 1, "method": "getIntent", "intent": copy.deepcopy(original)}
        app._enter_edit_mode()
        await pilot.pause()
        return original

    def value_field(self, app, key):
        n = next(n for n, row in app._edit_extra_rows.items() if row["key"] == key)
        return app.query_one(f"#ef_xv_{n}", ExtraValueInput)

    async def test_captured_values_are_safe_readonly_and_preserved_through_other_edits(self):
        app = self.make_app()
        extras = {f"unsafe{i}": {"type": "java.lang.String", "value": value,
            "noxenType": "string", "editable": True} for i, value in enumerate(UNSAFE_VALUES)}
        extras["list"] = {"type": "java.util.ArrayList", "noxenType": "string-list",
                          "value": "one,two\nlines,three", "editable": True}
        extras["truncated"] = {"type": "java.lang.String", "noxenType": "string",
                               "value": "partial\nvalue", "editable": False,
                               "structured": {"kind": "scalar", "truncated": True}}
        async with app.run_test(size=(120, 60)) as pilot:
            original = await self.open_editor(app, pilot, extras)
            for theme in ("noxen-dark", "noxen-light"):
                app.theme = theme
                await pilot.pause()
                for key, extra in extras.items():
                    field = self.value_field(app, key)
                    self.assertTrue(field.disabled)
                    self.assertEqual(json.loads(field.value), extra["value"])
                    self.assertFalse(needs_value_preview("".join(segment.text for segment in field.render_line(0))))
                self.assertEqual(app._collect_edit_mods(), [])
                self.assertEqual(app._collect_edit_draft()["extras"], extras)
            app.query_one("#ef_action", Input).value = "CHANGED"
            self.assertEqual(app._collect_edit_mods(), [("action", "", "CHANGED", "")])
            self.assertIsNone(app._apply_command_mod_to_editor(("extra_add", "unsafe0", r"literal\ntext", "string")))
            await pilot.pause()
            field = self.value_field(app, "unsafe0")
            self.assertFalse(field.disabled)
            self.assertEqual(field.value, r"literal\ntext")
            self.assertEqual(app._collect_edit_draft()["extras"]["unsafe1"], extras["unsafe1"])
            self.assertIsNone(app._apply_command_mod_to_editor(("extra_rem", "unsafe1", "", "")))
            await pilot.pause()
            self.assertNotIn("unsafe1", app._collect_edit_draft()["extras"])
            self.assertEqual(app._current_intercepted_entry["intent"], original)
            app._exit_edit_mode()
            app._enter_edit_mode()
            await pilot.pause()
            self.assertEqual(app._collect_edit_mods(), [])

    async def test_paste_is_atomic_and_identical_for_terminal_and_internal_clipboard(self):
        app = self.make_app()
        async with app.run_test(size=(120, 45)) as pilot:
            original = await self.open_editor(app, pilot, {
                "text": {"type": "java.lang.String", "value": "original", "noxenType": "string"},
            })
            field = self.value_field(app, "text")
            field.focus()
            await pilot.pause()
            for internal in (False, True):
                for text in UNSAFE_VALUES:
                    with self.subTest(internal=internal, text=repr(text)):
                        field.value = "original"
                        field.action_select_all()
                        selection = field.selection
                        with patch.object(app, "notify") as notify:
                            if internal:
                                with patch.object(type(app), "clipboard", new_callable=PropertyMock, return_value=text):
                                    field.action_paste()
                            else:
                                field.post_message(events.Paste(text))
                            await pilot.pause()
                            notify.assert_called_once()
                        self.assertEqual(field.value, "original")
                        self.assertEqual(field.selection, selection)
                        self.assertEqual(app._collect_edit_mods(), [])
                for text in SAFE_VALUES:
                    field.value = "original"
                    field.action_select_all()
                    if internal:
                        with patch.object(type(app), "clipboard", new_callable=PropertyMock, return_value=text):
                            field.action_paste()
                    else:
                        field.post_message(events.Paste(text))
                    await pilot.pause()
                    self.assertEqual(field.value, text or "original")
            self.assertEqual(app._current_intercepted_entry["intent"], original)

    async def test_new_row_and_command_created_control_value_remain_safe(self):
        app = self.make_app()
        async with app.run_test(size=(120, 45)) as pilot:
            await self.open_editor(app, pilot, {})
            app._add_edit_extra_row("new", "string", "original", is_new=True)
            await pilot.pause()
            field = self.value_field(app, "new")
            field.focus()
            field.post_message(events.Paste("first\nsecond"))
            await pilot.pause()
            self.assertEqual(field.value, "original")
            self.assertIsNone(app._apply_command_mod_to_editor(("extra_add", "new", "first\r\nsecond", "string")))
            await pilot.pause()
            field = self.value_field(app, "new")
            self.assertTrue(field.disabled)
            self.assertTrue(field.parent.parent.query_one("Select", Select).disabled)
            self.assertTrue(field.parent.parent.query_one(".ef_x_key_input", Input).disabled)
            self.assertEqual(app._collect_edit_draft()["extras"]["new"]["value"], "first\r\nsecond")
            self.assertFalse(needs_value_preview(field.value))
