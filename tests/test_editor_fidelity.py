import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rich.text import Text
from textual.widgets import Input

from noxen.app import NoxenApp
from noxen.db import ProjectDB
from noxen.exporting import write_history_export
from noxen.intent_mods import apply_mods_to_intent, confirmed_modification, diff_intents
from noxen.rendering import render_edit_context, render_intent_detail
from tests.ui_test_case import IsolatedAppTestCase


def intent(**fields):
    return {
        "component": None, "action": "", "data": "", "mimeType": "", "package": "",
        "categories": [], "flags": 0, "extras": {}, **fields,
    }


class FidelityTests(unittest.TestCase):
    def test_explicit_clear_of_an_empty_string_is_a_real_modification(self):
        for field, command in (("action", "action"), ("data", "data"), ("mimeType", "mime")):
            original = intent()
            draft = apply_mods_to_intent(original, [(command, "", "", "")])
            self.assertIsNone(draft[field])
            self.assertEqual(diff_intents(original, draft), [(command, "", "", "")])
            actual, changed, warning = confirmed_modification(original, {"ok": True, "infoIntent": draft})
            self.assertTrue(changed)
            self.assertIsNone(warning)
            self.assertIsNone(actual[field])

    def test_explicit_empty_category_commands_keep_exact_values(self):
        original = intent(categories=["A", " A "])
        added = apply_mods_to_intent(original, [("cat_add", "", "", "")])
        self.assertEqual(added["categories"], ["A", " A ", ""])
        self.assertEqual(diff_intents(original, added), [("cat_add", "", "", "")])
        removed = apply_mods_to_intent(added, [("cat_rem", "", " A ", "")])
        self.assertEqual(removed["categories"], ["A", ""])
        self.assertEqual(original["categories"], ["A", " A "])

    def test_detail_selector_nested_intents_and_changes_distinguish_empty(self):
        info = intent(categories=[""])
        nested = {"kind": "intent", "type": "android.content.Intent", **copy.deepcopy(info)}
        info["selector"] = nested
        info["extras"] = {"nested": {"structured": copy.deepcopy(nested), "editable": False}}
        plain = Text.from_markup(render_intent_detail({"id": 1, "method": "getIntent", "intent": info})).plain
        for label in ("Action", "Data (URI)", "MIME Type", "Package", "Category"):
            matching = [line for line in plain.splitlines() if label in line and ":" in line]
            self.assertTrue(matching, label)
            self.assertTrue(all(line.rstrip().endswith('""') for line in matching), matching)
        context = Text.from_markup(render_edit_context(info, {}, "getIntent")["selector"]).plain
        self.assertIn('""', context)
        modified = {**info, "mimeType": None}
        changes = Text.from_markup(render_intent_detail({"id": 1, "intent": modified, "original_intent": info})).plain
        self.assertIn('"" → (none)', changes)


class FidelityDBTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="noxen-fidelity-db-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "fidelity.noxen"
        self.db = ProjectDB(str(self.path))
        self.db.create("fidelity")
        self.addCleanup(self.db.close)

    def save(self, info):
        entry = {"timestamp": "2026-10-22T09:00:00Z", "class": "Example", "method": "getIntent", "intent": info}
        entry["id"] = self.db.save_intent(entry)
        return entry

    def reopen(self):
        self.db.close()
        return self.db.open_existing()

    def test_empty_null_and_missing_mime_round_trip_and_export(self):
        snapshots = [intent(), intent(action=None, data=None, mimeType=None, package=None), intent()]
        del snapshots[2]["mimeType"]
        for info in snapshots:
            self.save(info)
        stored = self.reopen()
        self.assertEqual([row["intent"] for row in stored], snapshots)
        output = str(self.path.with_suffix(".json"))
        with patch("noxen.exporting.timestamped_filename", return_value=output):
            write_history_export(stored)
        self.assertEqual([row["intent"] for row in json.loads(Path(output).read_text())], snapshots)
        self.assertNotIn("emptyMimeType", stored[0]["intent"])

    def test_modification_to_and_from_empty_removes_stale_marker(self):
        entry = self.save(intent(mimeType=None))
        before = entry["intent"]
        for value in ("", None, "text/plain", "", None):
            current = intent(mimeType=value)
            self.db.update_modified_intent(entry["id"], before, current)
            stored = self.reopen()[0]
            self.assertEqual(stored["intent"]["mimeType"], value)
            self.assertEqual(stored["original_intent"], before)
            before = current

    def test_old_rows_and_invalid_markers_are_not_reinterpreted(self):
        cases = [("", None, None), ("", {"emptyMimeType": "true"}, None),
                 (None, {"emptyMimeType": True}, "missing"),
                 ("text/plain", {"emptyMimeType": True}, "text/plain")]
        for mime_column, metadata, _ in cases:
            entry = self.save(intent())
            self.db._conn.execute("UPDATE intents SET mime_type=?, capture_metadata=? WHERE id=?",
                (mime_column, json.dumps(metadata) if metadata is not None else None, entry["id"]))
        self.db._conn.commit()
        for row, (_, _, expected) in zip(self.reopen(), cases):
            self.assertEqual(row["intent"].get("mimeType", "missing"), expected)


class FidelityEditorTests(IsolatedAppTestCase):
    def make_app(self):
        app = NoxenApp(SimpleNamespace(project=None,
            new_project=str(self.settings_path.parent / "fidelity.noxen"), skip_device_scan=True))
        self.addCleanup(app.db.close)
        return app

    async def open(self, app, pilot, info):
        app._current_intercepted_entry = {"id": 1, "method": "getIntent", "intent": copy.deepcopy(info)}
        app._enter_edit_mode()
        await pilot.pause()

    async def test_unchanged_categories_empty_fields_cancel_and_other_field_edits(self):
        app = self.make_app()
        categories = ["A", " A ", "   ", "", "\u00a0A\u00a0", "a\0b"]
        async with app.run_test(size=(120, 55)) as pilot:
            app.query_one("#main_tabs").active = "tab_intercept"
            for theme in ("noxen-dark", "noxen-light"):
                app.theme = theme
                for info in (intent(categories=categories), intent(action=None, data=None, mimeType=None, categories=categories)):
                    await self.open(app, pilot, info)
                    self.assertEqual(app._collect_edit_draft(), info)
                    self.assertEqual(app._collect_edit_mods(), [])
                    app.query_one("#ef_action", Input).value = "NEW"
                    self.assertEqual(app._collect_edit_mods(), [("action", "", "NEW", "")])
                    self.assertEqual(app._collect_edit_draft()["categories"], categories)
                    app.query_one("#ef_action", Input).value = info["action"] or ""
                    self.assertEqual(app._collect_edit_mods(), [])
                    app._exit_edit_mode()
                    await self.open(app, pilot, info)
                    self.assertEqual(app._collect_edit_mods(), [])
                    self.assertEqual(app._current_intercepted_entry["intent"], info)
                    app._exit_edit_mode()

    async def test_blank_new_rows_real_removal_and_exact_duplicates(self):
        app = self.make_app()
        async with app.run_test(size=(120, 55)) as pilot:
            app.query_one("#main_tabs").active = "tab_intercept"
            await self.open(app, pilot, intent(categories=["", "A", " A "]))
            app._add_edit_category_row("")
            await pilot.pause()
            self.assertEqual(app._collect_edit_mods(), [])
            number = next(n for n, row in app._edit_cat_rows.items() if row["original"] == "A")
            app.query_one(f"#ef_cv_{number}", Input).value = ""
            self.assertEqual(app._collect_edit_mods(), [("cat_rem", "", "A", "")])
            app._add_edit_category_row(" new ")
            await pilot.pause()
            self.assertIn(("cat_add", "", " new ", ""), app._collect_edit_mods())
            app._add_edit_category_row(" A ")
            await pilot.pause()
            with self.assertRaisesRegex(ValueError, "Duplicate category"):
                app._collect_edit_mods()

    async def test_commands_preserve_untouched_empty_fields_and_clear_explicitly(self):
        app = self.make_app()
        async with app.run_test(size=(120, 55)) as pilot:
            app.query_one("#main_tabs").active = "tab_intercept"
            await self.open(app, pilot, intent(categories=["A", " A "]))
            self.assertIsNone(app._apply_command_mod_to_editor(("cat_add", "", "", "")))
            await pilot.pause()
            self.assertEqual(app._collect_edit_draft()["categories"], ["A", " A ", ""])
            self.assertIsNone(app._apply_command_mod_to_editor(("cat_rem", "", " A ", "")))
            await pilot.pause()
            self.assertEqual(app._collect_edit_draft()["categories"], ["A", ""])
            self.assertIsNone(app._apply_command_mod_to_editor(("mime", "", "", "")))
            await pilot.pause()
            draft = app._collect_edit_draft()
            self.assertIsNone(draft["mimeType"])
            self.assertEqual(draft["action"], "")
            self.assertEqual(draft["data"], "")
            self.assertIn(("mime", "", "", ""), app._collect_edit_mods())

    async def test_remove_button_removes_only_the_selected_empty_category(self):
        app = self.make_app()
        async with app.run_test(size=(120, 55)) as pilot:
            app.query_one("#main_tabs").active = "tab_intercept"
            await self.open(app, pilot, intent(categories=["", "A", " A "]))
            number = next(n for n, row in app._edit_cat_rows.items() if row["original"] == "")
            button = app.query_one(f"#ef_crm_{number}")
            button.scroll_visible(animate=False)
            await pilot.pause()
            await pilot.click(button)
            await pilot.pause()
            self.assertEqual(app._collect_edit_draft()["categories"], ["A", " A "])
            self.assertEqual(app._collect_edit_mods(), [("cat_rem", "", "", "")])
