import unittest
from types import SimpleNamespace
from unittest.mock import patch

from noxen.app import NoxenApp


class AppLifecycleTests(unittest.TestCase):
    def test_target_detach_cleans_system_server_session(self):
        target_session = object()
        cleanup_calls = []
        intercept_states = []
        fake_app = SimpleNamespace(
            frida_session=target_session,
            system_server_session=SimpleNamespace(cleanup=lambda: cleanup_calls.append(True)),
            set_intercept_state=intercept_states.append,
            call_from_thread=lambda _callback: None,
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

    def test_stale_detach_callback_does_not_change_current_session(self):
        current_session = object()
        stale_session = object()
        cleanup_calls = []
        fake_app = SimpleNamespace(
            frida_session=current_session,
            system_server_session=SimpleNamespace(cleanup=lambda: cleanup_calls.append(True)),
            set_intercept_state=lambda _state: None,
            call_from_thread=lambda _callback: None,
        )
        fake_app._cleanup_system_server_session = (
            lambda async_cleanup=False: NoxenApp._cleanup_system_server_session(fake_app, async_cleanup)
        )

        NoxenApp._on_disconnected(fake_app, stale_session)

        self.assertIs(fake_app.frida_session, current_session)
        self.assertIsNotNone(fake_app.system_server_session)
        self.assertEqual(cleanup_calls, [])

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


class ImmediateThread:
    def __init__(self, target, daemon=False):
        self._target = target

    def start(self):
        self._target()


if __name__ == "__main__":
    unittest.main()
