import unittest
from types import SimpleNamespace
from unittest.mock import patch

from noxen.app import NoxenApp


class AppLifecycleTests(unittest.TestCase):
    def test_target_detach_cleans_system_server_session(self):
        target_session = object()
        cleanup_calls = []
        intercept_states = []
        intercept_clears = []
        info_clears = []
        fake_app = SimpleNamespace(
            frida_session=target_session,
            system_server_session=SimpleNamespace(cleanup=lambda: cleanup_calls.append(True)),
            set_intercept_state=intercept_states.append,
            call_from_thread=lambda callback: callback(),
            _connection_generation=3,
            query_one=lambda *_args, **_kwargs: (_ for _ in ()).throw(Exception("no UI")),
            _clear_intercept_output=lambda: intercept_clears.append(True),
            _clear_info_tab=lambda: info_clears.append(True),
        )
        fake_app._cleanup_system_server_session = (
            lambda async_cleanup=False: NoxenApp._cleanup_system_server_session(fake_app, async_cleanup)
        )

        with patch("noxen.app.threading.Thread", ImmediateThread):
            NoxenApp._on_disconnected(fake_app, target_session)

        self.assertIsNone(fake_app.frida_session)
        self.assertIsNone(fake_app.system_server_session)
        self.assertEqual(cleanup_calls, [True])
        self.assertEqual(intercept_states, [False])
        self.assertEqual(intercept_clears, [True])
        self.assertEqual(info_clears, [True])

    def test_stale_detach_callback_does_not_change_current_session(self):
        current_session = object()
        stale_session = object()
        cleanup_calls = []
        intercept_clears = []
        fake_app = SimpleNamespace(
            frida_session=current_session,
            system_server_session=SimpleNamespace(cleanup=lambda: cleanup_calls.append(True)),
            set_intercept_state=lambda _state: None,
            call_from_thread=lambda callback: callback(),
            _connection_generation=3,
            _clear_intercept_output=lambda: intercept_clears.append(True),
        )
        fake_app._cleanup_system_server_session = (
            lambda async_cleanup=False: NoxenApp._cleanup_system_server_session(fake_app, async_cleanup)
        )

        NoxenApp._on_disconnected(fake_app, stale_session)

        self.assertIs(fake_app.frida_session, current_session)
        self.assertIsNotNone(fake_app.system_server_session)
        self.assertEqual(cleanup_calls, [])
        self.assertEqual(intercept_clears, [])

    def test_queued_detach_ui_cleanup_does_not_touch_new_connection(self):
        detached_session = object()
        new_session = object()
        callbacks = []
        intercept_states = []
        intercept_clears = []
        fake_app = SimpleNamespace(
            frida_session=detached_session,
            system_server_session=None,
            _connection_generation=3,
            set_intercept_state=intercept_states.append,
            call_from_thread=callbacks.append,
            _clear_intercept_output=lambda: intercept_clears.append(True),
        )
        fake_app._cleanup_system_server_session = (
            lambda async_cleanup=False: NoxenApp._cleanup_system_server_session(fake_app, async_cleanup)
        )

        NoxenApp._on_disconnected(fake_app, detached_session)
        self.assertEqual(len(callbacks), 1)

        fake_app.frida_session = new_session
        fake_app._connection_generation = 4
        callbacks[0]()

        self.assertIs(fake_app.frida_session, new_session)
        self.assertEqual(intercept_states, [])
        self.assertEqual(intercept_clears, [])

    def test_intercept_display_uses_explicit_history_entry(self):
        first = {
            "id": 1,
            "class": "Example",
            "method": "getIntent",
            "intent": {},
            "stackTrace": [],
            "pendingIntentFlags": None,
            "attackSurface": {},
        }
        second = {
            **first,
            "id": 2,
            "method": "startActivity",
        }
        fake_app = SimpleNamespace(
            _all_intents=[first, second],
            _staged_mods=[],
            show_stack=False,
            stack_depth=0,
            query_one=lambda *_args, **_kwargs: (_ for _ in ()).throw(Exception("no UI")),
        )

        NoxenApp._on_intercept_display(fake_app, "rendered", entry_id=1, decision_id="decision-1")

        self.assertIs(fake_app._current_intercepted_entry, first)
        self.assertEqual(fake_app._current_intercept_id, 1)
        self.assertEqual(fake_app._current_decision_id, "decision-1")

    def test_intercept_display_without_entry_does_not_keep_stale_current_intent(self):
        fake_app = SimpleNamespace(
            _all_intents=[],
            _current_intercept_id=99,
            _current_decision_id="old-decision",
            _current_intercepted_entry={"id": 99},
            _staged_mods=[("action", "", "old", "")],
            _write_rich=lambda *_args, **_kwargs: None,
        )

        NoxenApp._on_intercept_display(fake_app, "rendered", entry_id=None, decision_id="decision-2")

        self.assertIsNone(fake_app._current_intercept_id)
        self.assertIsNone(fake_app._current_intercepted_entry)
        self.assertEqual(fake_app._current_decision_id, "decision-2")
        self.assertEqual(fake_app._staged_mods, [])

    def test_clear_intercept_output_discards_invalid_runtime_state(self):
        fake_app = SimpleNamespace(
            _current_intercepted_entry={"id": 42},
            _current_intercept_id=42,
            _current_decision_id="decision-dead-process",
            _staged_mods=[("action", "", "modified", "")],
            query_one=lambda *_args, **_kwargs: (_ for _ in ()).throw(Exception("no UI")),
        )

        NoxenApp._clear_intercept_output(fake_app)

        self.assertIsNone(fake_app._current_intercepted_entry)
        self.assertIsNone(fake_app._current_intercept_id)
        self.assertIsNone(fake_app._current_decision_id)
        self.assertEqual(fake_app._staged_mods, [])

    def test_history_table_applies_saved_column_widths(self):
        table = _FakeHistoryTable()
        fake_app = SimpleNamespace(
            _history_selected_entry=None,
            _history_visible_cols={"id", "time", "method", "class"},
            _history_column_widths={"time": 19, "method": 18, "class": 40},
            _sort_column="id",
            _sort_reverse=True,
            query_one=lambda *_args, **_kwargs: table,
            _get_filtered_sorted=lambda: [],
            _fill_table_rows=lambda _table, _filtered: None,
            _restore_cursor=lambda _table, _filtered, _saved: None,
        )

        NoxenApp._refresh_history_table(fake_app)

        self.assertEqual(table.columns["id"], None)
        self.assertEqual(table.columns["time"], 19)
        self.assertEqual(table.columns["method"], 18)
        self.assertEqual(table.columns["class"], 40)


class ImmediateThread:
    def __init__(self, target, daemon=False):
        self._target = target

    def start(self):
        self._target()


class _FakeHistoryTable:
    def __init__(self):
        self.columns = {}

    def clear(self, columns=False):
        if columns:
            self.columns = {}

    def add_column(self, _label, *, key=None, width=None):
        self.columns[key] = width


if __name__ == "__main__":
    unittest.main()
