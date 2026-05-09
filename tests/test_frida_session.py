import sys
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from noxen.agent_loader import HooksLoadResult
from noxen.filters import FilterManager
from noxen.frida_session import FridaSession, SessionConfig


class SessionConfigTests(unittest.TestCase):
    def test_target_label_uses_spawn_package_first(self):
        config = SessionConfig(spawn_package="com.example.app", attach_name="Example", attach_pid=1234)

        self.assertEqual(config.target_label(), "com.example.app")

    def test_target_label_uses_attach_name(self):
        config = SessionConfig(attach_name="Example")

        self.assertEqual(config.target_label(), "Example")

    def test_target_label_formats_pid(self):
        config = SessionConfig(attach_pid=1234)

        self.assertEqual(config.target_label(), "PID 1234")

    def test_target_label_is_empty_without_target(self):
        self.assertEqual(SessionConfig().target_label(), "")


class FridaSessionMessageTests(unittest.TestCase):
    def test_js_messages_are_normalized_to_consistent_log_shape(self):
        self.assertEqual(
            FridaSession._format_js_message("[+] Hooks ready"),
            "[dim]agent        [/dim] [#26a368]OK   [/#26a368] Hooks ready",
        )
        self.assertEqual(
            FridaSession._format_js_message("[~] Hook skipped"),
            "[dim]agent        [/dim] [yellow]WARN [/yellow] Hook skipped",
        )
        self.assertEqual(
            FridaSession._format_js_message("[!] Hook failed"),
            "[dim]agent        [/dim] [red]ERROR[/red] Hook failed",
        )

    def test_hold_events_are_routed_outside_history(self):
        starts = []
        ends = []
        history = []
        session = FridaSession(
            SessionConfig(attach_pid=1),
            FilterManager(),
            log_cb=lambda _text: None,
            intercept_cb=lambda _state: None,
            get_stack=lambda: (False, 0),
            history_cb=lambda payload, counter: history.append((payload, counter)),
            hold_start_cb=starts.append,
            hold_end_cb=ends.append,
        )

        session.on_message({"type": "send", "payload": {"noxenEvent": "hold_start", "holdId": "h1"}}, None)
        session.on_message({"type": "send", "payload": {"noxenEvent": "hold_end", "holdId": "h1"}}, None)

        self.assertEqual(starts, [{"noxenEvent": "hold_start", "holdId": "h1"}])
        self.assertEqual(ends, [{"noxenEvent": "hold_end", "holdId": "h1"}])
        self.assertEqual(history, [])

    def test_regular_payload_still_reaches_history(self):
        history = []
        fake_script = SimpleNamespace(exports_sync=SimpleNamespace(forward=lambda _decision_id=None: True))
        session = FridaSession(
            SessionConfig(attach_pid=1),
            FilterManager(),
            log_cb=lambda _text: None,
            intercept_cb=lambda _state: None,
            get_stack=lambda: (False, 0),
            history_cb=lambda payload, counter: history.append((payload, counter)) or 7,
            outcome_cb=lambda _db_id, _outcome: None,
        )
        session._script = fake_script

        session.on_message({
            "type": "send",
            "payload": {
                "className": "Example",
                "methodName": "getIntent",
                "infoIntent": {},
                "stackTrace": [],
            },
        }, None)

        self.assertEqual(len(history), 1)
        self.assertEqual(history[0][0]["methodName"], "getIntent")

    def test_non_blocking_payload_reaches_history_without_intercept_ui(self):
        history = []
        outcomes = []
        intercept_logs = []
        intercept_states = []
        forward_calls = []
        fake_script = SimpleNamespace(
            exports_sync=SimpleNamespace(forward=lambda decision_id=None: forward_calls.append(decision_id) or True)
        )
        session = FridaSession(
            SessionConfig(attach_pid=1),
            FilterManager(),
            log_cb=lambda _text: None,
            intercept_cb=intercept_states.append,
            get_stack=lambda: (False, 0),
            history_cb=lambda payload, counter: history.append((payload, counter)) or 9,
            outcome_cb=lambda db_id, outcome: outcomes.append((db_id, outcome)),
            intercept_log_cb=lambda *args: intercept_logs.append(args),
        )
        session._script = fake_script

        session.on_message({
            "type": "send",
            "payload": {
                "className": "Example",
                "methodName": "getIntent",
                "infoIntent": {},
                "stackTrace": [],
                "decision": {"required": False, "id": None, "reason": "busy"},
            },
        }, None)

        self.assertEqual(len(history), 1)
        self.assertEqual(outcomes, [(9, "forwarded")])
        self.assertEqual(intercept_logs, [])
        self.assertEqual(intercept_states, [])
        self.assertEqual(forward_calls, [])

    def test_hidden_blocking_payload_auto_forwards_matching_decision(self):
        forwarded = threading.Event()
        forward_calls = []
        outcomes = []
        fake_script = SimpleNamespace(
            exports_sync=SimpleNamespace(
                forward=lambda decision_id=None: forward_calls.append(decision_id) or forwarded.set() or True
            )
        )
        filters = FilterManager()
        filters.add("focus", ["method=sendBroadcast"])
        session = FridaSession(
            SessionConfig(attach_pid=1),
            filters,
            log_cb=lambda _text: None,
            intercept_cb=lambda _state: None,
            get_stack=lambda: (False, 0),
            history_cb=lambda _payload, _counter: 11,
            outcome_cb=lambda db_id, outcome: outcomes.append((db_id, outcome)),
        )
        session._script = fake_script

        session.on_message({
            "type": "send",
            "payload": {
                "className": "Example",
                "methodName": "getIntent",
                "infoIntent": {},
                "stackTrace": [],
                "decision": {"required": True, "id": "decision-1", "reason": None},
            },
        }, None)

        self.assertTrue(forwarded.wait(timeout=1))
        self.assertEqual(forward_calls, ["decision-1"])
        self.assertEqual(outcomes, [(11, "forwarded")])

    def test_visible_blocking_payload_passes_history_id_and_decision_to_intercept_ui(self):
        intercept_logs = []
        intercept_states = []
        outcomes = []
        session = FridaSession(
            SessionConfig(attach_pid=1),
            FilterManager(),
            log_cb=lambda _text: None,
            intercept_cb=intercept_states.append,
            get_stack=lambda: (False, 0),
            history_cb=lambda _payload, _counter: 13,
            outcome_cb=lambda db_id, outcome: outcomes.append((db_id, outcome)),
            intercept_log_cb=lambda *args: intercept_logs.append(args),
        )

        session.on_message({
            "type": "send",
            "payload": {
                "className": "Example",
                "methodName": "getIntent",
                "infoIntent": {},
                "stackTrace": [],
                "decision": {"required": True, "id": "decision-2", "reason": None},
            },
        }, None)

        self.assertEqual(len(intercept_logs), 1)
        self.assertIn("INTERCEPTED", intercept_logs[0][0])
        self.assertEqual(intercept_logs[0][1:], (13, "decision-2"))
        self.assertEqual(intercept_states, [True])
        self.assertEqual(outcomes, [])

    def test_rpc_resume_methods_pass_decision_id(self):
        calls = []
        session = FridaSession(
            SessionConfig(attach_pid=1),
            FilterManager(),
            log_cb=lambda _text: None,
            intercept_cb=lambda _state: None,
            get_stack=lambda: (False, 0),
        )
        session._script = SimpleNamespace(
            exports_sync=SimpleNamespace(
                forward=lambda decision_id=None: calls.append(("forward", decision_id)) or True,
                drop=lambda decision_id=None: calls.append(("drop", decision_id)) or True,
                stage_mod=lambda *args: calls.append(("stage_mod", args)) or True,
            )
        )

        self.assertTrue(session.forward("decision-3"))
        self.assertTrue(session.drop("decision-3"))
        self.assertTrue(session.stage_mod("action", "", "android.intent.action.VIEW", "", "decision-3"))

        self.assertEqual(calls, [
            ("forward", "decision-3"),
            ("drop", "decision-3"),
            ("stage_mod", ("action", "", "android.intent.action.VIEW", "", "decision-3")),
        ])


class FridaSessionLifecycleTests(unittest.TestCase):
    def test_cleanup_invalidates_connection_still_in_progress(self):
        attached = threading.Event()
        release_attach = threading.Event()
        fake_session = _FakeFridaSession()

        class FakeDevice:
            def attach(self, _target):
                attached.set()
                release_attach.wait(timeout=2)
                return fake_session

        fake_frida = SimpleNamespace(get_device=lambda _device_id, timeout=5: FakeDevice())
        connected = []
        logs = []
        session = FridaSession(
            SessionConfig(attach_name="Example"),
            FilterManager(),
            log_cb=logs.append,
            intercept_cb=lambda _state: None,
            get_stack=lambda: (False, 0),
        )
        session.connected_cb = lambda: connected.append(True)

        with patch.dict(sys.modules, {"frida": fake_frida}), patch(
            "noxen.frida_session.load_hook_config",
            return_value=HooksLoadResult([], []),
        ):
            session.connect("device-1")
            self.assertTrue(attached.wait(timeout=2))
            session.cleanup()
            release_attach.set()
            session._connect_thread.join(timeout=2)

        self.assertTrue(fake_session.detached)
        self.assertIsNone(session._session)
        self.assertIsNone(session._script)
        self.assertEqual(connected, [])


class _FakeFridaSession:
    def __init__(self):
        self.detached = False
        self.callbacks = {}

    def on(self, event_name, callback):
        self.callbacks[event_name] = callback

    def detach(self):
        self.detached = True


if __name__ == "__main__":
    unittest.main()
