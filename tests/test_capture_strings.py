import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rich.text import Text
from textual.widgets import Input, Static

from noxen.app import NoxenApp
from noxen.db import ProjectDB
from noxen.exporting import write_history_export
from noxen.intent_mods import confirmed_modification
from noxen.rendering import history_search_matches, render_intent_detail
from tests.ui_test_case import IsolatedAppTestCase


def captured_intent():
    return {
        "component": None, "action": "before\0after", "data": "content://host/a\0b",
        "mimeType": "text/plain", "flags": 0, "categories": ["cat\0tail"],
        "extras": {"key\0tail": {
            "type": "java.lang.String", "value": "a\0b\x1bc", "editable": True,
            "noxenType": "string", "structuredVersion": 1,
            "structured": {"kind": "scalar", "type": "java.lang.String", "value": "a\0b\x1bc", "noxenType": "string"},
        }},
        "errors": ["package could not be read (InvalidUTF16)"],
        "unreadableFields": ["package"], "package": None,
    }


class CaptureStringTests(unittest.TestCase):
    def test_render_search_database_and_export_keep_the_complete_strings(self):
        info = captured_intent()
        entry = {"timestamp": "2026-10-22T08:00:00Z", "class": "Example", "method": "getIntent", "intent": info}
        with tempfile.TemporaryDirectory() as directory:
            db = ProjectDB(str(Path(directory) / "strings.noxen"))
            try:
                db.create("strings")
                entry["id"] = db.save_intent(entry)
                db.close()
                stored = db.open_existing()[0]
                self.assertEqual(stored["intent"], info)
                self.assertTrue(history_search_matches(stored, "after"))
                self.assertTrue(history_search_matches(stored, "InvalidUTF16"))
                plain = Text.from_markup(render_intent_detail(stored)).plain
                self.assertIn(r"before\x00after", plain)
                self.assertIn(r"key\x00tail", plain)
                self.assertIn(r"a\x00b\x1bc", plain)
                self.assertIn("Read warning", plain)
                self.assertNotIn("\0", plain)
                self.assertNotIn("\x1b", plain)
                path = str(Path(directory) / "strings.json")
                with patch("noxen.exporting.timestamped_filename", return_value=path):
                    write_history_export([stored])
                self.assertEqual(json.loads(Path(path).read_text())[0]["intent"], info)
            finally:
                db.close()

    def test_unreadable_or_truncated_result_is_not_a_false_confirmed_change(self):
        original = {**captured_intent(), "action": "original", "errors": [], "unreadableFields": []}
        for marker in ("unreadableFields", "truncatedFields"):
            actual = {**copy.deepcopy(original), "action": None, marker: ["action"]}
            restored, changed, warning = confirmed_modification(original, {"ok": True, "infoIntent": actual})
            self.assertFalse(changed)
            self.assertEqual(restored["action"], "original")
            self.assertIn("string fields could not be fully verified", warning)


class CaptureStringEditorTests(IsolatedAppTestCase):
    async def test_previews_do_not_become_edits_and_commands_replace_raw_fields(self):
        app = NoxenApp(SimpleNamespace(project=None,
            new_project=str(self.settings_path.parent / "strings.noxen"), skip_device_scan=True))
        self.addCleanup(app.db.close)
        async with app.run_test(size=(120, 55)) as pilot:
            info = captured_intent()
            app.query_one("#main_tabs").active = "tab_intercept"
            app._current_intercepted_entry = {"id": 1, "method": "getIntent", "intent": copy.deepcopy(info)}
            app._enter_edit_mode()
            await pilot.pause()
            for widget in ("#ef_action", "#ef_data", ".ef_cat_input"):
                control = app.query_one(widget, Input)
                self.assertTrue(control.disabled)
                self.assertNotIn("\0", control.value)
                self.assertIn(r"\u0000", control.value)
            self.assertTrue(app.query_one("#ef_capture_errors", Static).display)
            self.assertEqual(app._collect_edit_mods(), [])
            self.assertEqual(app._collect_edit_draft(), info)
            app.query_one("#ef_mime", Input).value = "text/html"
            self.assertEqual(app._collect_edit_mods(), [("mime", "", "text/html", "")])
            self.assertIsNone(app._apply_command_mod_to_editor(("action", "", "NEW", "")))
            await pilot.pause()
            self.assertFalse(app.query_one("#ef_action", Input).disabled)
            self.assertEqual(app._collect_edit_draft()["action"], "NEW")
            self.assertEqual(app._collect_edit_draft()["data"], info["data"])
            self.assertIsNone(app._apply_command_mod_to_editor(("extra_rem", "key\0tail", "", "")))
            await pilot.pause()
            self.assertEqual(app._collect_edit_draft()["extras"], {})
            app._exit_edit_mode()
            self.assertEqual(app._current_intercepted_entry["intent"], info)

    async def test_truncated_field_is_readonly_and_is_not_rewritten_on_forward(self):
        app = NoxenApp(SimpleNamespace(project=None,
            new_project=str(self.settings_path.parent / "truncated.noxen"), skip_device_scan=True))
        self.addCleanup(app.db.close)
        async with app.run_test(size=(100, 40)) as pilot:
            info = {**captured_intent(), "action": "partial", "truncatedFields": ["action"]}
            app._current_intercepted_entry = {"id": 1, "method": "getIntent", "intent": copy.deepcopy(info)}
            app._enter_edit_mode()
            await pilot.pause()
            self.assertTrue(app.query_one("#ef_action", Input).disabled)
            self.assertEqual(app._collect_edit_mods(), [])
