import asyncio
import json
import threading
from types import SimpleNamespace
from unittest.mock import patch

from textual.widgets import DataTable, RichLog

from noxen.app import NoxenApp
from noxen.exporting import write_history_export
from noxen.frida_session import SessionConfig
from tests.ui_test_case import IsolatedAppTestCase


def payload(number, required=False):
    return {"noxenEvent": "intent", "protocolVersion": 1,
            "className": "Example", "methodName": "getIntent", "stackTrace": [],
            "infoIntent": {"action": f"EVENT_{number}", "extras": {}, "flags": 0, "categories": []},
            "decision": {"required": required, "id": f"decision-{number}" if required else None}}


class HistoryBatchingTests(IsolatedAppTestCase):
    def make_app(self):
        app = NoxenApp(SimpleNamespace(project=None,
            new_project=str(self.settings_path.parent / "session.noxen"), skip_device_scan=True))
        self.addCleanup(app.db.close)
        app._init_session(SessionConfig(attach_pid=1))
        return app

    def emit(self, app, start, stop):
        for number in range(start, stop):
            app.frida_session.on_message({"type": "send", "payload": payload(number)}, None)

    async def test_hidden_captures_are_saved_without_rendering_then_appear_on_open(self):
        app = self.make_app()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            with patch.object(app, "_refresh_rows_only", wraps=app._refresh_rows_only) as rows, patch.object(
                app, "_refresh_history_table", wraps=app._refresh_history_table
            ) as table_refresh:
                await asyncio.to_thread(self.emit, app, 0, 60)
                await pilot.pause(.2)
                rows.assert_not_called()
                table_refresh.assert_not_called()
                self.assertEqual(len(app._all_intents), 60)
                self.assertTrue(all(e["outcome"] == "forwarded" for e in app.db._load_all()))
                self.assertTrue(app._history_refresh_pending)
                export_path = self.settings_path.parent / "history.json"
                with patch("noxen.exporting.timestamped_filename", return_value=str(export_path)):
                    write_history_export(app._all_intents)
                self.assertEqual(len(json.loads(export_path.read_text())), 60)
                app.query_one("#main_tabs").active = "tab_history"
                await pilot.pause()
                table = app.query_one("#history_table", DataTable)
                self.assertEqual(table.row_count, 60)
                self.assertEqual([key.value for key in table.rows], [str(i) for i in range(60, 0, -1)])
                self.assertEqual(table_refresh.call_count, 1)
                self.assertFalse(app._history_refresh_pending)

    async def test_many_callbacks_share_one_refresh_without_waiting_for_the_ui(self):
        with patch("noxen.app.HISTORY_REFRESH_INTERVAL", 60):
            app = self.make_app()
            async with app.run_test(size=(120, 40)) as pilot:
                app.query_one("#main_tabs").active = "tab_history"
                await pilot.pause()
                with patch.object(app, "_refresh_rows_only", wraps=app._refresh_rows_only) as rebuild:
                    with patch.object(app, "call_from_thread", side_effect=AssertionError("UI wait in capture callback")):
                        await asyncio.to_thread(self.emit, app, 0, 30)
                    rebuild.assert_not_called()
                    self.assertEqual(len(app.db._load_all()), 30)
                    app._do_history_refresh()
                    app._do_history_refresh()
                    self.assertEqual(rebuild.call_count, 1)
                    self.assertEqual(app.query_one("#history_table", DataTable).row_count, 30)

    async def test_outcome_without_a_new_capture_updates_selected_detail_on_the_timer(self):
        app = self.make_app()
        async with app.run_test(size=(120, 40)) as pilot:
            app.query_one("#main_tabs").active = "tab_history"
            await pilot.pause()
            await asyncio.to_thread(self.emit, app, 0, 1)
            await pilot.pause(.2)
            self.assertEqual(app.query_one("#history_table", DataTable).row_count, 1)
            await asyncio.to_thread(app._update_outcome, 1, "dropped")
            await pilot.pause(.2)
            detail = app.query_one("#history_detail", RichLog)
            self.assertIn("DROPPED", "\n".join(line.text for line in detail.lines))
            self.assertEqual(app.db._load_all()[0]["outcome"], "dropped")
            self.assertFalse(app._history_refresh_pending)

    async def test_capture_during_rebuild_stays_pending_for_the_next_refresh(self):
        with patch("noxen.app.HISTORY_REFRESH_INTERVAL", 60):
            app = self.make_app()
            async with app.run_test(size=(120, 40)) as pilot:
                app.query_one("#main_tabs").active = "tab_history"
                await pilot.pause()
                await asyncio.to_thread(self.emit, app, 0, 1)
                fill = app._fill_table_rows
                errors = []

                def incoming():
                    try:
                        self.emit(app, 1, 2)
                    except Exception as error:
                        errors.append(error)

                def concurrent_fill(table, entries):
                    thread = threading.Thread(target=incoming, daemon=True)
                    thread.start()
                    thread.join(3)
                    self.assertFalse(thread.is_alive())
                    fill(table, entries)

                with patch.object(app, "_fill_table_rows", side_effect=concurrent_fill):
                    app._do_history_refresh()
                self.assertEqual(errors, [])
                self.assertTrue(app._history_refresh_pending)
                self.assertEqual(app.query_one("#history_table", DataTable).row_count, 1)
                app._do_history_refresh()
                self.assertEqual(app.query_one("#history_table", DataTable).row_count, 2)
                self.assertFalse(app._history_refresh_pending)
                self.assertEqual(len(app.db._load_all()), 2)

    async def test_intercept_display_does_not_wait_for_history_timer(self):
        with patch("noxen.app.HISTORY_REFRESH_INTERVAL", 60):
            app = self.make_app()
            async with app.run_test(size=(120, 40)) as pilot:
                app.query_one("#main_tabs").active = "tab_intercept"
                await pilot.pause()
                await asyncio.to_thread(app.frida_session.on_message,
                    {"type": "send", "payload": payload(7, required=True)}, None)
                self.assertTrue(app._intent_blocked)
                self.assertEqual(app._current_decision_id, "decision-7")
                self.assertEqual(app._current_intercepted_entry["intent"]["action"], "EVENT_7")
                self.assertTrue(app._history_refresh_pending)
                self.assertEqual(app.query_one("#history_table", DataTable).row_count, 0)

    async def test_hidden_column_changes_are_applied_when_history_is_opened(self):
        app = self.make_app()
        async with app.run_test(size=(120, 40)) as pilot:
            app.query_one("#main_tabs").active = "tab_history"
            await pilot.pause()
            await asyncio.to_thread(self.emit, app, 0, 3)
            await pilot.pause(.2)
            app.query_one("#main_tabs").active = "tab_intercept"
            await pilot.pause()
            with patch.object(app, "_fill_table_rows", wraps=app._fill_table_rows) as fill:
                app._on_columns_changed({"id", "action"})
                app._on_history_column_widths_changed({"action": 37})
                app._sort_column, app._sort_reverse = "action", False
                app._refresh_history_table()
                fill.assert_not_called()
                self.assertTrue(app._history_columns_dirty)
                app.query_one("#main_tabs").active = "tab_history"
                await pilot.pause()
                table = app.query_one("#history_table", DataTable)
                self.assertEqual([key.value for key in table.columns], ["id", "action"])
                action_column = next(column for key, column in table.columns.items() if key.value == "action")
                self.assertEqual(action_column.width, 37)
                self.assertIn("↑", action_column.label.plain)
                self.assertEqual(table.row_count, 3)
                self.assertFalse(app._history_columns_dirty)

    async def test_delayed_cursor_restore_does_not_override_a_new_user_selection(self):
        with patch("noxen.app.HISTORY_REFRESH_INTERVAL", 60):
            app = self.make_app()
            async with app.run_test(size=(120, 40)) as pilot:
                app.query_one("#main_tabs").active = "tab_history"
                await pilot.pause()
                await asyncio.to_thread(self.emit, app, 0, 20)
                app._do_history_refresh()
                await pilot.pause(.2)
                table = app.query_one("#history_table", DataTable)
                table.move_cursor(row=5)
                await pilot.pause(.2)
                await asyncio.to_thread(app._update_outcome, 20, "dropped")
                app._do_history_refresh()
                table.move_cursor(row=8)
                await pilot.pause(.2)
                self.assertEqual(table.cursor_row, 8)
                self.assertEqual(app._history_selected_entry["id"], 12)
