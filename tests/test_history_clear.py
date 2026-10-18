import asyncio
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from textual.widgets import DataTable, RichLog

from tests.ui_test_case import IsolatedAppTestCase, SettingsIsolationMixin

from noxen.app import NoxenApp


def payload(action):
    return {"className": "Example", "methodName": "getIntent", "stackTrace": [],
            "infoIntent": {"action": action, "extras": {}, "categories": [], "flags": 0}}


class _ObservedLock:
    """Expose a competing thread's lock attempt without relying on sleeps."""
    def __init__(self, thread_name, attempted):
        self.lock = threading.Lock()
        self.thread_name = thread_name
        self.attempted = attempted

    def __enter__(self):
        if threading.current_thread().name == self.thread_name:
            self.attempted.set()
        self.lock.acquire()

    def __exit__(self, *args):
        self.lock.release()


class HistoryClearTests(SettingsIsolationMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.app = NoxenApp(SimpleNamespace(
            new_project=str(Path(directory.name) / "history.noxen"),
            project=None, skip_device_scan=True,
        ))
        self.addCleanup(self.app.db.close)
        for name in ("write_log", "call_from_thread"):
            patcher = patch.object(self.app, name)
            patcher.start()
            self.addCleanup(patcher.stop)

    def capture(self, action):
        return self.app._on_history_intent(payload(action), 1)

    def test_failed_clear_preserves_memory_selection_search_and_pending_rows(self):
        self.capture("KEEP")
        entry = self.app._all_intents[0]
        self.app._history_selected_entry = entry
        index = self.app._history_search_index.copy()
        with patch.object(self.app.db, "clear_intents", side_effect=sqlite3.OperationalError("locked")):
            self.app.action_clear_history()
        self.assertEqual(self.app._all_intents, [entry])
        self.assertIs(self.app._history_selected_entry, entry)
        self.assertEqual(self.app._history_search_index, index)
        self.assertEqual(self.app._pending_append, [entry])
        self.assertTrue(self.app._history_refresh_pending)
        self.assertEqual(len(self.app.db._load_all()), 1)
        self.assertIn("Could not clear History", self.app.write_log.call_args.args[0])

    def test_successful_clear_discards_queued_refresh_but_keeps_blocked_intent(self):
        row_id = self.capture("BLOCKED")
        self.app._on_intercept_display("", row_id, "blocked-decision")
        current = self.app._current_intercepted_entry
        self.app._staged_mods = [("action", "", "EDITED", "")]
        self.app._intent_blocked = True
        scheduled = self.app.call_from_thread.call_args.args[0]
        self.app.action_clear_history()
        self.assertEqual(self.app._all_intents, [])
        self.assertEqual(self.app._pending_append, [])
        self.assertEqual(self.app._history_search_index, {})
        self.assertFalse(self.app._history_refresh_pending)
        self.assertEqual(self.app.db._load_all(), [])
        with patch.object(self.app, "_refresh_history_table") as rebuild:
            scheduled()
            rebuild.assert_not_called()
        self.assertIs(self.app._current_intercepted_entry, current)
        self.assertEqual(self.app._current_decision_id, "blocked-decision")
        self.assertTrue(self.app._intent_blocked)
        self.assertEqual(self.app._staged_mods, [("action", "", "EDITED", "")])
        self.capture("AFTER")
        self.assertTrue(self.app._history_refresh_pending)
        self.assertEqual(len(self.app._pending_append), 1)

    def test_clear_with_closed_database_does_not_discard_unsaved_captures(self):
        self.app.db.close()
        self.capture("UNSAVED")
        self.app.action_clear_history()
        self.assertEqual(len(self.app._all_intents), 1)
        self.assertIn("persistence_error", self.app._all_intents[0])

    def test_real_commit_failure_rolls_back_deleted_rows(self):
        self.capture("KEEP")
        conn = self.app.db._conn
        conn.executescript("""
            CREATE TABLE clear_parent (id INTEGER PRIMARY KEY);
            CREATE TABLE clear_check (
                parent_id INTEGER REFERENCES clear_parent(id) DEFERRABLE INITIALLY DEFERRED
            );
            CREATE TRIGGER fail_clear AFTER DELETE ON intents
            BEGIN INSERT INTO clear_check VALUES (1); END;
        """)
        self.app.action_clear_history()
        self.assertFalse(conn.in_transaction)
        self.assertEqual(len(self.app._all_intents), 1)
        self.assertEqual(len(self.app.db._load_all()), 1)
        conn.execute("DROP TRIGGER fail_clear")
        self.app.action_clear_history()
        self.assertEqual(self.app._all_intents, [])
        self.assertEqual(self.app.db._load_all(), [])

    def test_capture_and_clear_have_a_consistent_boundary_in_both_orders(self):
        for first in ("capture", "clear"):
            with self.subTest(first=first):
                self.app.action_clear_history()
                entered, release, attempted = threading.Event(), threading.Event(), threading.Event()
                second = "clear" if first == "capture" else "capture"
                self.app._history_lock = _ObservedLock(second, attempted)
                real_operation = self.app.db.save_intent if first == "capture" else self.app.db.clear_intents
                errors = []

                def delay(*args):
                    result = real_operation(*args)
                    entered.set()
                    if not release.wait(3):
                        raise RuntimeError("test release timed out")
                    return result

                def run(operation):
                    try:
                        self.capture("CONCURRENT") if operation == "capture" else self.app.action_clear_history()
                    except Exception as error:
                        errors.append(error)

                method = "save_intent" if first == "capture" else "clear_intents"
                with patch.object(self.app.db, method, side_effect=delay):
                    threads = [threading.Thread(target=run, args=(name,), name=name) for name in (first, second)]
                    threads[0].start()
                    try:
                        self.assertTrue(entered.wait(3))
                        threads[1].start()
                        self.assertTrue(attempted.wait(3))
                    finally:
                        release.set()
                        for thread in threads:
                            if thread.ident is not None:
                                thread.join(3)
                self.assertFalse(any(thread.is_alive() for thread in threads))
                self.assertEqual(errors, [])
                expected = [] if first == "capture" else ["CONCURRENT"]
                self.assertEqual([e["intent"]["action"] for e in self.app._all_intents], expected)
                self.assertEqual([e["intent"]["action"] for e in self.app.db._load_all()], expected)

    def test_capture_releases_history_lock_before_waiting_for_ui(self):
        def ui_callback(*args, **kwargs):
            self.assertTrue(self.app._history_lock.acquire(blocking=False))
            self.app._history_lock.release()
        self.app.call_from_thread.side_effect = ui_callback
        self.capture("CURRENT")
        self.app._history_refresh_pending = False
        self.app.write_log.side_effect = ui_callback
        with patch.object(self.app.db, "save_intent", side_effect=sqlite3.OperationalError("disk full")):
            self.capture("UNSAVED")


class HistoryClearUITests(IsolatedAppTestCase):
    async def test_failed_clear_keeps_table_and_successful_clear_rejects_stale_appends(self):
        asyncio.get_running_loop().slow_callback_duration = 1.0
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(
                new_project=str(Path(directory) / "ui.noxen"), project=None, skip_device_scan=True,
            ))
            async with app.run_test(size=(120, 40)) as pilot:
                app.query_one("#main_tabs").active = "tab_history"
                with patch.object(app, "call_from_thread", side_effect=lambda callback, *args: callback(*args)):
                    app._on_history_intent(payload("KEEP"), 1)
                await pilot.pause()
                table = app.query_one("#history_table", DataTable)
                detail = app.query_one("#history_detail", RichLog)
                selected = app._history_selected_entry
                lines = list(detail.lines)
                with patch.object(app.db, "clear_intents", side_effect=sqlite3.OperationalError("locked")):
                    app.action_clear_history()
                await pilot.pause()
                self.assertEqual(table.row_count, 1)
                self.assertIs(app._history_selected_entry, selected)
                self.assertEqual(detail.lines, lines)
                callbacks = []
                with patch.object(app, "call_from_thread", side_effect=callbacks.append):
                    app._on_history_intent(payload("QUEUED_BEFORE_CLEAR"), 2)
                app.action_clear_history()
                self.assertEqual(table.row_count, 0)
                with patch.object(app, "call_from_thread", side_effect=lambda callback, *args: callback(*args)):
                    app._on_history_intent(payload("AFTER_CLEAR"), 3)
                for callback in callbacks:
                    callback()
                await pilot.pause()
                self.assertEqual(table.row_count, 1)
                self.assertEqual([e["intent"]["action"] for e in app._all_intents], ["AFTER_CLEAR"])
                self.assertEqual([e["intent"]["action"] for e in app.db._load_all()], ["AFTER_CLEAR"])
