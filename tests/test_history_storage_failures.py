import asyncio
import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from textual.widgets import DataTable, Input

from tests.ui_test_case import IsolatedAppTestCase, SettingsIsolationMixin

from noxen.app import NoxenApp
from noxen.exporting import write_history_export
from noxen.frida_session import ModificationResume, SessionConfig
from noxen.rendering import render_intent_detail


def payload(action, decision="decision-current", required=True):
    return {
        "noxenEvent": "intent", "protocolVersion": 1,
        "className": "Example", "methodName": "getIntent", "stackTrace": [],
        "infoIntent": {"action": action, "data": None, "mimeType": None,
                       "flags": 0, "categories": [], "extras": {}},
        "decision": {"required": required, "id": decision if required else None},
    }


class HistoryStorageFailureTests(SettingsIsolationMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.app = NoxenApp(SimpleNamespace(
            new_project=str(Path(self.directory.name) / "test.noxen"),
            project=None, skip_device_scan=True,
        ))
        self.addCleanup(self.app.db.close)
        for name, replacement in (
            ("call_from_thread", lambda callback, *args: callback(*args)),
            ("write_log", None),
        ):
            patcher = patch.object(self.app, name, **({"side_effect": replacement} if replacement else {}))
            patcher.start()
            self.addCleanup(patcher.stop)

    def capture(self, action, **kwargs):
        return self.app._on_history_intent(payload(action, **kwargs), 1)

    def test_failed_save_keeps_correct_capture_and_recovers_without_id_collisions(self):
        previous_id = self.capture("PREVIOUS")
        with patch.object(self.app.db, "save_intent", side_effect=sqlite3.OperationalError("disk full")):
            first = self.capture("CURRENT")
            second = self.capture("NEXT")
        saved = self.capture("RECOVERED")
        self.assertEqual((previous_id, first, second, saved), (1, -1, -2, 2))
        self.app._on_intercept_display("", first, "decision-current")
        self.assertEqual(self.app._current_intercepted_entry["intent"]["action"], "CURRENT")
        self.assertEqual(self.app._current_decision_id, "decision-current")
        self.assertEqual(self.app._current_intercept_id, first)
        self.assertIn("STORAGE WARNING", render_intent_detail(self.app._current_intercepted_entry))
        export_path = Path(self.directory.name) / "history.json"
        with patch("noxen.exporting.timestamped_filename", return_value=str(export_path)):
            write_history_export(self.app._all_intents)
        exported = json.loads(export_path.read_text())
        self.assertEqual(exported[1]["intent"]["action"], "CURRENT")
        self.assertIn("persistence_error", exported[1])
        self.assertEqual([e["intent"]["action"] for e in self.app.db._load_all()], ["PREVIOUS", "RECOVERED"])
        self.app.write_log.assert_called()

    def test_unavailable_database_and_clear_never_reuse_temporary_ids(self):
        with patch.object(self.app.db, "save_intent", return_value=0):
            first = self.capture("FIRST")
            self.app.action_clear_history()
            second = self.capture("SECOND")
        self.assertEqual((first, second), (-1, -2))

    def test_real_sqlite_commit_failure_rolls_back_and_allows_next_capture(self):
        conn = self.app.db._conn
        conn.executescript("""
            CREATE TABLE save_parent (id INTEGER PRIMARY KEY);
            CREATE TABLE save_check (
                parent_id INTEGER REFERENCES save_parent(id) DEFERRABLE INITIALLY DEFERRED
            );
            CREATE TRIGGER fail_save AFTER INSERT ON intents
            BEGIN INSERT INTO save_check VALUES (1); END;
        """)
        failed = self.capture("FAILED_COMMIT")
        self.assertEqual(failed, -1)
        self.assertFalse(conn.in_transaction)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM intents").fetchone()[0], 0)
        conn.execute("DROP TRIGGER fail_save")
        saved = self.capture("RECOVERED")
        self.assertEqual(saved, 1)
        self.assertEqual([e["intent"]["action"] for e in self.app.db._load_all()], ["RECOVERED"])

    def test_unsaved_modifications_and_outcome_stay_in_memory_without_database_updates(self):
        with patch.object(self.app.db, "save_intent", side_effect=sqlite3.OperationalError("read only")):
            entry_id = self.capture("CURRENT")
        entry = self.app._all_intents[-1]
        self.app._on_intercept_display("", entry_id, "decision-current")
        actual = {**copy.deepcopy(entry["intent"]), "action": "MODIFIED"}
        result = ModificationResume(True, {"ok": True, "infoIntent": actual})
        with patch.object(self.app.db, "update_modified_intent") as modified, patch.object(
            self.app.db, "update_outcome"
        ) as outcome, patch.object(self.app.db, "update_modification_error") as warning:
            self.app._finalize_forward(entry_id, entry, [("action", "", "MODIFIED", "")], result)
            self.app._persist_history_update(entry_id, self.app.db.update_modification_error, "test")
            modified.assert_not_called()
            outcome.assert_not_called()
            warning.assert_not_called()
        self.assertEqual(entry["intent"]["action"], "MODIFIED")
        self.assertEqual(entry["original_intent"]["action"], "CURRENT")
        self.assertEqual(entry["outcome"], "modified_forwarded")
        self.assertIsNone(self.app._current_decision_id)

    def test_real_sqlite_update_commit_failures_roll_back(self):
        entry_id = self.capture("CURRENT")
        conn = self.app.db._conn
        conn.executescript("""
            CREATE TABLE save_parent (id INTEGER PRIMARY KEY);
            CREATE TABLE save_check (
                parent_id INTEGER REFERENCES save_parent(id) DEFERRABLE INITIALLY DEFERRED
            );
            CREATE TRIGGER fail_update AFTER UPDATE ON intents
            BEGIN INSERT INTO save_check VALUES (1); END;
        """)
        original = self.app._all_intents[0]["intent"]
        for update, args in (
            (self.app.db.update_outcome, ("dropped",)),
            (self.app.db.update_modification_error, ("test warning",)),
            (self.app.db.update_modified_intent, (original, {**original, "action": "MODIFIED"})),
            (self.app.db.update_capture_metadata, ({"extrasMeta": {"omitted": 20}},)),
        ):
            with self.subTest(update=update.__name__):
                self.app._persist_history_update(entry_id, update, *args)
                self.assertFalse(conn.in_transaction)
                stored = self.app.db._load_all()[0]
                self.assertIsNone(stored["outcome"])
                self.assertIsNone(stored["modification_error"])
                self.assertIsNone(stored["original_intent"])
                self.assertEqual(stored["intent"]["action"], "CURRENT")
                self.assertNotIn("extrasMeta", stored["intent"])

    def test_failed_updates_do_not_prevent_forward_finalization(self):
        entry_id = self.capture("CURRENT")
        entry = self.app._all_intents[-1]
        self.app._on_intercept_display("", entry_id, "decision-current")
        actual = {**copy.deepcopy(entry["intent"]), "action": "MODIFIED"}
        result = ModificationResume(True, {"ok": True, "infoIntent": actual})
        with patch.object(self.app.db, "update_modified_intent", side_effect=sqlite3.OperationalError("disk full")), patch.object(
            self.app.db, "update_outcome", side_effect=sqlite3.OperationalError("database locked")
        ):
            self.app._finalize_forward(entry_id, entry, [("action", "", "MODIFIED", "")], result)
        self.assertEqual(entry["intent"]["action"], "MODIFIED")
        self.assertEqual(entry["outcome"], "modified_forwarded")
        self.assertIn("outdated", entry["persistence_error"])
        self.assertIsNone(self.app._current_decision_id)
        self.assertEqual(self.app.db._load_all()[0]["intent"]["action"], "CURRENT")

    def test_filtered_and_observed_events_keep_outcomes_despite_failed_save(self):
        self.app._init_session(SessionConfig(attach_pid=1))
        session = self.app.frida_session
        with patch.object(self.app.db, "save_intent", side_effect=sqlite3.OperationalError("disk full")):
            session.on_message({"type": "send", "payload": payload("OBSERVED", required=False)}, None)
            self.app.filter_manager.add("ignore", ["action=FILTERED"])
            with patch.object(session, "_forward_async") as forward:
                session.on_message({"type": "send", "payload": payload("FILTERED")}, None)
                forward.assert_called_once_with("decision-current", -2)
        self.assertEqual(self.app._all_intents[0]["outcome"], "forwarded")

    def test_incomplete_result_metadata_is_saved_without_confirmed_field_changes(self):
        entry_id = self.capture("CURRENT")
        entry = self.app._all_intents[-1]
        self.app._on_intercept_display("", entry_id, "decision-current")
        actual = {**copy.deepcopy(entry["intent"]), "extras": {"partial": {}},
                  "extrasMeta": {"count": 70, "capturedCount": 50, "omitted": 20}}
        result = ModificationResume(True, {"ok": True, "infoIntent": actual})
        self.app._finalize_forward(entry_id, entry, [("extra_add", "new", "value", "string")], result)
        stored = self.app.db._load_all()[0]
        self.assertEqual(stored["intent"]["extrasMeta"], actual["extrasMeta"])
        self.assertEqual(stored["intent"]["extras"], {})
        self.assertEqual(stored["outcome"], "forwarded")
        self.assertIsNone(stored["original_intent"])
        self.assertIn("fully verified", stored["modification_error"])
        self.assertIn("20 additional extras omitted", render_intent_detail(stored))

    def test_failed_metadata_update_still_finishes_forward_and_warns_about_storage(self):
        entry_id = self.capture("CURRENT")
        entry = self.app._all_intents[-1]
        self.app._on_intercept_display("", entry_id, "decision-current")
        actual = {**copy.deepcopy(entry["intent"]), "extrasMeta": {"error": "Unreadable"}}
        result = ModificationResume(True, {"ok": True, "infoIntent": actual})
        with patch.object(self.app.db, "update_capture_metadata", side_effect=sqlite3.OperationalError("disk full")):
            self.app._finalize_forward(entry_id, entry, [("extra_add", "new", "value", "string")], result)
        self.assertIn("outdated", entry["persistence_error"])
        self.assertEqual(entry["intent"]["extrasMeta"], actual["extrasMeta"])
        self.assertEqual(entry["outcome"], "forwarded")
        self.assertIsNone(self.app._current_decision_id)


class HistoryStorageFailureUITests(IsolatedAppTestCase):
    async def test_editor_forward_and_drop_use_the_unsaved_capture(self):
        asyncio.get_running_loop().slow_callback_duration = 1.0
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(
                new_project=str(Path(directory) / "ui.noxen"), project=None, skip_device_scan=True,
            ))
            async with app.run_test(size=(120, 40)) as pilot:
                app.query_one("#main_tabs").active = "tab_intercept"
                app._init_session(SessionConfig(attach_pid=1))
                session = app.frida_session
                session._ready = True
                drops, forwards = [], []
                session.drop = lambda decision: drops.append(decision) or True

                def forward(mods, decision):
                    forwards.append((mods, decision))
                    actual = copy.deepcopy(app._current_intercepted_entry["intent"])
                    actual["action"] = "EDITED"
                    return ModificationResume(True, {"ok": True, "infoIntent": actual})

                session.forward_with_mods = forward
                session.is_ready = lambda: True
                with patch.object(app, "call_from_thread", side_effect=lambda callback, *args: callback(*args)):
                    app._on_history_intent(payload("PREVIOUS"), 1)
                for decision in ("edit-current", "drop-current"):
                    with patch.object(app.db, "save_intent", side_effect=sqlite3.OperationalError("disk full")), patch.object(
                        app, "call_from_thread", side_effect=lambda callback, *args: callback(*args)
                    ):
                        session.on_message({
                            "type": "send", "payload": payload("CURRENT", decision),
                        }, None)
                    await pilot.pause()
                    self.assertEqual(app._current_intercepted_entry["intent"]["action"], "CURRENT")
                    if decision == "edit-current":
                        app._enter_edit_mode()
                        await pilot.pause()
                        app.query_one("#ef_action", Input).value = "EDITED"
                        with patch.object(app, "call_from_thread", side_effect=lambda callback, *args: callback(*args)), patch.object(
                            app, "_apply_mods_and_forward_worker",
                            side_effect=lambda mods: NoxenApp._apply_mods_and_forward_worker.__wrapped__(app, mods),
                        ):
                            NoxenApp.process_command_worker.__wrapped__(app, "forward")
                    else:
                        with patch.object(app, "call_from_thread", side_effect=lambda callback, *args: callback(*args)):
                            NoxenApp.process_command_worker.__wrapped__(app, "drop")
                    await pilot.pause()
                    self.assertIsNone(app._current_decision_id)
                    self.assertFalse(app._intent_blocked)
                self.assertEqual(forwards, [([("action", "", "EDITED", "")], "edit-current")])
                self.assertEqual(drops, ["drop-current"])
                self.assertEqual(app._all_intents[0]["intent"]["action"], "PREVIOUS")
                self.assertEqual(app._all_intents[1]["outcome"], "modified_forwarded")
                self.assertEqual(app._all_intents[2]["outcome"], "dropped")
                self.assertEqual(app.query_one("#history_table", DataTable).row_count, 3)
