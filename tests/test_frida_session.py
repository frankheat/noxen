import sys
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from noxen.agent_loader import ExtraScriptError, ExtraScriptSource, HookConfigError, HooksLoadResult, ScriptLoadResult
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
    def test_extra_script_messages_and_invalid_events_never_change_interception(self):
        valid = {
            "noxenEvent": "intent", "protocolVersion": 1,
            "className": "Example", "methodName": "getIntent",
            "infoIntent": {}, "stackTrace": [],
            "decision": {"required": True, "id": "decision-1"},
        }
        payloads = [
            {"foo": "bar"}, {}, None, ["hello"], 42, True, "[*] Extra script ready",
            {key: value for key, value in valid.items() if key != "noxenEvent"},
            {**valid, "noxenEvent": "custom_event"},
            {key: value for key, value in valid.items() if key != "protocolVersion"},
            {**valid, "protocolVersion": 2},
            {**valid, "protocolVersion": True},
            {**valid, "protocolVersion": "1"},
            {**valid, "className": ""},
            {**valid, "methodName": []},
            {**valid, "infoIntent": None},
            {**valid, "infoIntent": []},
            {**valid, "stackTrace": "frame"},
            {**valid, "stackTrace": [{}]},
            {**valid, "decision": None},
            {**valid, "decision": {"required": "false", "id": "decision-1"}},
            {**valid, "decision": {"required": True}},
            {**valid, "decision": {"required": True, "id": ""}},
            {**valid, "decision": {"required": True, "id": " "}},
            {**valid, "decision": {"required": True, "id": 1}},
            {**valid, "decision": {"required": False, "id": "decision-1"}},
        ]
        for blocking in (True, False):
            for payload in payloads:
                with self.subTest(blocking=blocking, payload=payload):
                    history, outcomes, intercepts, logs = [], [], [], []
                    session = FridaSession(
                        SessionConfig(attach_pid=1), FilterManager(), logs.append,
                        intercept_cb=intercepts.append,
                        get_stack=lambda: self.fail("Non-Intent message requested rendering"),
                        history_cb=lambda *args: history.append(args),
                        outcome_cb=lambda *args: outcomes.append(args),
                        intercept_log_cb=lambda *args: intercepts.append(args),
                    )
                    session._blocking_enabled = blocking
                    with patch.object(session, "_forward_async") as forward:
                        session.on_message({"type": "send", "payload": payload}, b"custom data")
                        forward.assert_not_called()
                    self.assertEqual(history, [])
                    self.assertEqual(outcomes, [])
                    self.assertEqual(intercepts, [])
                    self.assertEqual(session._history_counter, 0)
                    self.assertEqual(session._intercept_counter, 0)
                    self.assertEqual(len(logs), 1)

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

    def test_async_hook_report_is_logged_outside_history(self):
        logs = []
        history = []
        session = FridaSession(
            SessionConfig(attach_pid=1),
            FilterManager(),
            log_cb=logs.append,
            intercept_cb=lambda _state: None,
            get_stack=lambda: (False, 0),
            history_cb=lambda payload, counter: history.append((payload, counter)),
        )
        session._hooks_result = HooksLoadResult(
            hooks=[{}], messages=[], sources=("custom hook[0]",), custom_count=1,
        )

        session.on_message({
            "type": "send",
            "payload": {
                "noxenEvent": "hook_report",
                "report": {"installed": 1, "installedIndices": [0], "skipped": [], "failed": []},
            },
        }, None)

        self.assertEqual(history, [])
        self.assertEqual(session._history_counter, 0)
        self.assertIn("Hooks: 1 installed, 0 skipped, 0 failed", logs[-1])

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
                "noxenEvent": "intent",
                "protocolVersion": 1,
                "className": "Example",
                "methodName": "getIntent",
                "infoIntent": {},
                "stackTrace": [],
                "decision": {"required": False, "id": None},
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
                "noxenEvent": "intent",
                "protocolVersion": 1,
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
                "noxenEvent": "intent",
                "protocolVersion": 1,
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
                "noxenEvent": "intent",
                "protocolVersion": 1,
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
        def confirm(method, mods, decision_id):
            calls.append((method, mods, decision_id))
            session.on_message({"type": "send", "payload": {
                "noxenEvent": "modification_result", "decisionId": decision_id,
                "ok": True, "infoIntent": {"action": "confirmed"},
            }}, None)
            return True

        session._script = SimpleNamespace(
            exports_sync=SimpleNamespace(
                forward=lambda decision_id=None: calls.append(("forward", decision_id)) or True,
                forward_with_mods=lambda mods, decision_id=None: confirm("forward_with_mods", mods, decision_id),
                drop=lambda decision_id=None: calls.append(("drop", decision_id)) or True,
                stage_mod=lambda *args: calls.append(("stage_mod", args)) or True,
                intercept_off_with_mods=lambda mods, decision_id=None: confirm("intercept_off_with_mods", mods, decision_id),
            )
        )

        self.assertTrue(session.forward("decision-3"))
        mods = [("extra_add", "count", "5", "int")]
        forward_result = session.forward_with_mods(mods, "decision-3")
        self.assertTrue(forward_result)
        self.assertEqual(forward_result.report["infoIntent"]["action"], "confirmed")
        self.assertTrue(session.drop("decision-3"))
        self.assertTrue(session.stage_mod("action", "", "android.intent.action.VIEW", "", "decision-3"))
        self.assertTrue(session.intercept_off_with_mods(mods, "decision-3"))

        self.assertEqual(calls, [
            ("forward", "decision-3"),
            ("forward_with_mods", [{
                "type": "extra_add", "key": "count", "val": "5", "extraType": "int",
            }], "decision-3"),
            ("drop", "decision-3"),
            ("stage_mod", ("action", "", "android.intent.action.VIEW", "", "decision-3")),
            ("intercept_off_with_mods", [{
                "type": "extra_add", "key": "count", "val": "5", "extraType": "int",
            }], "decision-3"),
        ])

    def test_missing_modification_confirmation_is_not_reported_as_success(self):
        session = FridaSession(
            SessionConfig(attach_pid=1), FilterManager(), log_cb=lambda _text: None,
            intercept_cb=lambda _state: None, get_stack=lambda: (False, 0),
        )
        session._script = SimpleNamespace(exports_sync=SimpleNamespace(
            forward_with_mods=lambda _mods, _decision_id: True,
        ))
        with patch("noxen.frida_session.MODIFICATION_CONFIRM_TIMEOUT", 0.01):
            result = session.forward_with_mods([("action", "", "changed", "")], "decision-4")
        self.assertTrue(result.resumed)
        self.assertIsNone(result.report)
        self.assertEqual(session._pending_modifications, {})

    def test_unmatched_modification_result_cannot_confirm_other_decision(self):
        session = FridaSession(
            SessionConfig(attach_pid=1), FilterManager(), log_cb=lambda _text: None,
            intercept_cb=lambda _state: None, get_stack=lambda: (False, 0),
        )
        def resume(_mods, _decision_id):
            session.on_message({"type": "send", "payload": {
                "noxenEvent": "modification_result", "decisionId": "different",
                "ok": True, "infoIntent": {"action": "wrong"},
            }}, None)
            return True
        session._script = SimpleNamespace(exports_sync=SimpleNamespace(forward_with_mods=resume))
        with patch("noxen.frida_session.MODIFICATION_CONFIRM_TIMEOUT", 0.01):
            result = session.forward_with_mods([("action", "", "changed", "")], "decision-5")
        self.assertIsNone(result.report)

    def test_cleanup_releases_worker_waiting_for_modification_result(self):
        rpc_returned = threading.Event()
        results = []
        session = FridaSession(
            SessionConfig(attach_pid=1), FilterManager(), log_cb=lambda _text: None,
            intercept_cb=lambda _state: None, get_stack=lambda: (False, 0),
        )
        session._script = SimpleNamespace(exports_sync=SimpleNamespace(
            forward_with_mods=lambda _mods, _decision_id: rpc_returned.set() or True,
            interceptoff=lambda: None,
        ))
        worker = threading.Thread(target=lambda: results.append(
            session.forward_with_mods([("action", "", "changed", "")], "decision-6")
        ))
        worker.start()
        self.assertTrue(rpc_returned.wait(1))
        session.cleanup()
        worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertTrue(results[0].resumed)
        self.assertIsNone(results[0].report)


class FridaSessionLifecycleTests(unittest.TestCase):
    def test_extra_script_read_failure_never_contacts_device(self):
        setup = self._hook_setup()
        session, _script, _native, _device, _logs, connected, failures, _warnings = setup
        session._config.extra_script = "missing.js"
        fake_frida = SimpleNamespace(get_device=lambda *_args, **_kwargs: self.fail("Device contacted"))
        with patch.dict(sys.modules, {"frida": fake_frida}), patch(
            "noxen.frida_session.load_agent_script", side_effect=ExtraScriptError("missing.js")
        ):
            session.connect("device-1")
            session._connect_thread.join(2)
        self.assertFalse(session._connect_thread.is_alive())
        self.assertEqual(connected, [])
        self.assertEqual(failures, [("extra-script", "missing.js")])

    def test_extra_script_execution_precedes_hooks_and_resume_in_spawn_and_attach(self):
        for spawn in (True, False):
            with self.subTest(spawn=spawn):
                setup = self._hook_setup(spawn=spawn)
                session, script, _native, device, logs, connected, failures, _warnings = setup
                extra = ExtraScriptSource("/extra.js", "send('ready');")
                session._config.extra_script_source = extra
                calls = []

                def execute(name, code):
                    self.assertFalse(device.resumed.is_set())
                    self.assertFalse(script.proxy_called.is_set())
                    calls.append((name, code))
                    return True

                def proxy(_hooks):
                    self.assertEqual(calls, [(extra.path, extra.code)])
                    script.emit_report({"installed": 1, "installedIndices": [0], "skipped": [], "failed": []})
                    return {"pending": True}

                script.exports_sync.load_extra_script = execute
                script.exports_sync.proxy = proxy
                fake_frida = SimpleNamespace(get_device=lambda *_args, **_kwargs: device)
                with patch.dict(sys.modules, {"frida": fake_frida}), patch(
                    "noxen.frida_session.load_agent_script", return_value=ScriptLoadResult("agent", [], extra)
                ) as loader:
                    session.connect("device-1")
                    session._connect_thread.join(2)
                loader.assert_called_once_with(extra)
                self.assertFalse(session._connect_thread.is_alive())
                self.assertEqual(connected, [True])
                self.assertEqual(failures, [])
                self.assertTrue(any("initial code executed" in line for line in logs))

    def test_extra_script_execution_failure_cleans_up_without_installing_hooks(self):
        for spawn in (True, False):
            for result in (RuntimeError("/extra.js:3: broken"), None, False):
                with self.subTest(spawn=spawn, result=result):
                    setup = self._hook_setup(spawn=spawn)
                    session, script, native, device, _logs, connected, failures, _warnings = setup
                    extra = ExtraScriptSource("/extra.js", "broken")

                    def execute(_name, _code):
                        if isinstance(result, Exception):
                            raise result
                        return result

                    script.exports_sync.load_extra_script = execute
                    fake_frida = SimpleNamespace(get_device=lambda *_args, **_kwargs: device)
                    with patch.dict(sys.modules, {"frida": fake_frida}), patch(
                        "noxen.frida_session.load_agent_script", return_value=ScriptLoadResult("agent", [], extra)
                    ):
                        session.connect("device-1")
                        session._connect_thread.join(2)
                    self.assertFalse(session._connect_thread.is_alive())
                    self.assertEqual(connected, [])
                    self.assertFalse(script.proxy_called.is_set())
                    self.assertEqual(failures[0][0], "extra-script")
                    self.assertTrue(native.detached)
                    self.assertEqual(device.killed, [42] if spawn else [])

    def test_javascript_error_logs_full_stack(self):
        session, _script, _native, _device, logs, *_rest = self._hook_setup()
        session.on_message({"type": "error", "description": "broken", "stack": "Error: broken\n at /extra.js:7"}, None)
        self.assertIn("/extra.js:7", logs[-1])

    def _hook_setup(self, spawn=True):
        script = _FakeHookScript()
        native_session = _FakeHookNativeSession(script)
        device = _FakeHookDevice(native_session)
        logs, connected, failures, warnings = [], [], [], []
        config = SessionConfig(
            spawn_package="dev.example" if spawn else None,
            attach_pid=None if spawn else 42,
            validated_hooks=HooksLoadResult(
                hooks=[{"clazz": "Example", "method": "run", "args": []}],
                messages=[], sources=("custom hook[0]",), custom_count=1,
            ),
        )
        session = FridaSession(
            config, FilterManager(), log_cb=logs.append,
            intercept_cb=lambda _state: None, get_stack=lambda: (False, 0),
        )
        session.connected_cb = lambda: connected.append(True)
        session.connection_failed_cb = lambda stage, error: failures.append((stage, str(error)))
        session.hook_warning_cb = warnings.append
        return session, script, native_session, device, logs, connected, failures, warnings

    def _run_hook_setup(self, setup, report=None, timeout=False):
        session, script, _native, device, _logs, _connected, _failures, _warnings = setup
        fake_frida = SimpleNamespace(get_device=lambda _id, timeout=5: device)
        with patch.dict(sys.modules, {"frida": fake_frida}), patch(
            "noxen.frida_session.load_agent_script",
            return_value=ScriptLoadResult("agent", []),
        ), patch("noxen.frida_session.HOOK_REPORT_TIMEOUT", 0.03 if timeout else 1):
            session.connect("device-1")
            self.assertTrue(script.proxy_called.wait(1))
            if report is not None:
                script.emit_report(report)
            session._connect_thread.join(2)
        self.assertFalse(session._connect_thread.is_alive())

    def test_connection_waits_for_hook_report_after_resume(self):
        setup = self._hook_setup()
        session, script, _native, device, _logs, connected, failures, _warnings = setup
        fake_frida = SimpleNamespace(get_device=lambda _id, timeout=5: device)
        with patch.dict(sys.modules, {"frida": fake_frida}), patch(
            "noxen.frida_session.load_agent_script",
            return_value=ScriptLoadResult("agent", []),
        ):
            session.connect("device-1")
            self.assertTrue(device.resumed.wait(1))
            self.assertEqual(connected, [])
            self.assertFalse(session.is_ready())
            script.emit_report({"installed": 1, "installedIndices": [0], "skipped": [], "failed": []})
            session._connect_thread.join(2)
        self.assertEqual(connected, [True])
        self.assertTrue(session.is_ready())
        self.assertEqual(failures, [])

    def test_attach_also_waits_for_hook_report(self):
        setup = self._hook_setup(spawn=False)
        self._run_hook_setup(setup, {
            "installed": 1, "installedIndices": [0], "skipped": [], "failed": [],
        })
        self.assertEqual(setup[5], [True])
        self.assertEqual(setup[6], [])
        self.assertTrue(setup[0].is_ready())

    def test_fatal_report_never_marks_session_connected(self):
        setup = self._hook_setup()
        self._run_hook_setup(setup, {"fatal": "Unable to find fields in java/lang/Thread"})
        _session, _script, native, device, logs, connected, failures, _warnings = setup
        self.assertEqual(connected, [])
        self.assertEqual(failures[0][0], "hooks")
        self.assertIn("Hook initialization failed", failures[0][1])
        self.assertTrue(native.detached)
        self.assertEqual(device.killed, [])
        self.assertTrue(any("Unable to find fields" in line for line in logs))

    def test_missing_report_times_out_without_green_state(self):
        setup = self._hook_setup()
        self._run_hook_setup(setup, timeout=True)
        _session, _script, native, device, _logs, connected, failures, _warnings = setup
        self.assertEqual(connected, [])
        self.assertEqual(failures[0][0], "hooks")
        self.assertIn("timed out", failures[0][1])
        self.assertTrue(native.detached)
        self.assertEqual(device.killed, [])

    def test_zero_hooks_is_not_a_ready_session(self):
        setup = self._hook_setup()
        self._run_hook_setup(setup, {"installed": 0, "installedIndices": [], "skipped": [], "failed": []})
        self.assertEqual(setup[5], [])
        self.assertIn("No hooks were installed", setup[6][0][1])

    def test_malformed_success_report_is_rejected(self):
        setup = self._hook_setup()
        self._run_hook_setup(setup, {
            "installed": 1, "installedIndices": [], "skipped": [], "failed": [],
        })
        self.assertEqual(setup[5], [])
        self.assertIn("Malformed hook registration report", setup[6][0][1])

    def test_partial_report_connects_with_warning(self):
        setup = self._hook_setup()
        self._run_hook_setup(setup, {
            "installed": 1, "installedIndices": [0], "skipped": [],
            "failed": [{"index": 1, "signature": "Example.other()", "error": "not found"}],
        })
        self.assertEqual(setup[5], [True])
        self.assertEqual(setup[6], [])
        self.assertTrue(any("Hook setup incomplete" in warning for warning in setup[7]))

    def test_detach_during_hook_setup_does_not_wait_for_timeout(self):
        setup = self._hook_setup()
        session, script, native, device, _logs, connected, failures, _warnings = setup
        fake_frida = SimpleNamespace(get_device=lambda _id, timeout=5: device)
        with patch.dict(sys.modules, {"frida": fake_frida}), patch(
            "noxen.frida_session.load_agent_script",
            return_value=ScriptLoadResult("agent", []),
        ):
            session.connect("device-1")
            self.assertTrue(device.resumed.wait(1))
            native.callbacks["detached"]("process-terminated", None)
            session._connect_thread.join(2)
        self.assertEqual(connected, [])
        self.assertEqual(failures[0][0], "hooks")

    def test_cleanup_during_hook_setup_ignores_late_report(self):
        setup = self._hook_setup()
        session, script, _native, device, _logs, connected, failures, _warnings = setup
        fake_frida = SimpleNamespace(get_device=lambda _id, timeout=5: device)
        with patch.dict(sys.modules, {"frida": fake_frida}), patch(
            "noxen.frida_session.load_agent_script",
            return_value=ScriptLoadResult("agent", []),
        ):
            session.connect("device-1")
            self.assertTrue(device.resumed.wait(1))
            session.cleanup()
            script.emit_report({"installed": 1, "installedIndices": [0], "skipped": [], "failed": []})
            session._connect_thread.join(2)
        self.assertEqual(connected, [])
        self.assertEqual(failures, [])
        self.assertFalse(session.is_ready())

    def test_hook_config_failure_is_reported_instead_of_killing_connect_thread(self):
        error = HookConfigError("custom", ["top-level value must be a JSON array"])
        failures = []
        logs = []
        session = FridaSession(
            SessionConfig(attach_name="Example"),
            FilterManager(),
            log_cb=logs.append,
            intercept_cb=lambda _state: None,
            get_stack=lambda: (False, 0),
        )
        session.connection_failed_cb = lambda stage, exc: failures.append((stage, exc))

        with patch("noxen.frida_session.load_hook_config", side_effect=error):
            session.connect("device-1")
            session._connect_thread.join(timeout=2)

        self.assertEqual(failures, [("configuration", error)])
        self.assertIn("Connection failed", logs[-1])

    def test_hook_registration_report_identifies_sources_and_failures(self):
        logs = []
        session = FridaSession(
            SessionConfig(attach_pid=1),
            FilterManager(),
            log_cb=logs.append,
            intercept_cb=lambda _state: None,
            get_stack=lambda: (False, 0),
        )
        hooks = HooksLoadResult(
            hooks=[{}, {}, {}],
            messages=[],
            sources=("default hook[0]", "custom hook[0]", "custom hook[1]"),
            custom_count=2,
        )
        warnings = []
        session.hook_warning_cb = warnings.append

        session._log_hook_report({
            "installed": 1,
            "installedIndices": [0],
            "skipped": [{"index": 1, "reason": "requires API 34, device API 31"}],
            "failed": [{
                "index": 2,
                "signature": "dev.example.Receiver.onReceive(android.content.Intent)",
                "error": "overload not found",
            }],
        }, hooks)

        self.assertIn("Skipped custom hook[0]", logs[0])
        self.assertIn("Failed custom hook[1]", logs[1])
        self.assertIn("Hooks: 1 installed, 1 skipped, 1 failed", logs[2])
        self.assertIn("No custom hooks were installed", logs[3])
        self.assertEqual(warnings, ["No custom hooks were installed. See Log for details."])

    def test_connection_failure_reports_stage_and_exception(self):
        class ServerNotRunningError(Exception):
            pass

        error = ServerNotRunningError("server is not running")
        fake_frida = SimpleNamespace(get_device=lambda _device_id, timeout=5: (_ for _ in ()).throw(error))
        failures = []
        logs = []
        session = FridaSession(
            SessionConfig(attach_name="Example"),
            FilterManager(),
            log_cb=logs.append,
            intercept_cb=lambda _state: None,
            get_stack=lambda: (False, 0),
        )
        session.connection_failed_cb = lambda stage, exc: failures.append((stage, exc))

        with patch.dict(sys.modules, {"frida": fake_frida}), patch(
            "noxen.frida_session.load_hook_config",
            return_value=HooksLoadResult([], []),
        ):
            session.connect("device-1")
            session._connect_thread.join(timeout=2)

        self.assertEqual(failures, [("device", error)])
        self.assertIn("Connection failed: server is not running", logs[-1])

    def test_spawn_attach_failure_kills_suspended_process(self):
        killed = []

        class FakeDevice:
            def spawn(self, _packages):
                return 42

            def attach(self, _pid):
                raise RuntimeError("attach failed")

            def kill(self, pid):
                killed.append(pid)

        fake_frida = SimpleNamespace(get_device=lambda _device_id, timeout=5: FakeDevice())
        failures = []
        session = FridaSession(
            SessionConfig(spawn_package="dev.example"),
            FilterManager(),
            log_cb=lambda _text: None,
            intercept_cb=lambda _state: None,
            get_stack=lambda: (False, 0),
        )
        session.connection_failed_cb = lambda stage, exc: failures.append((stage, str(exc)))

        with patch.dict(sys.modules, {"frida": fake_frida}), patch(
            "noxen.frida_session.load_hook_config",
            return_value=HooksLoadResult([], []),
        ):
            session.connect("device-1")
            session._connect_thread.join(timeout=2)

        self.assertEqual(killed, [42])
        self.assertEqual(failures, [("spawn", "attach failed")])

    def test_cancelled_connection_cleans_only_its_spawned_process(self):
        for mode in ("spawn", "name", "pid"):
            for kill_fails in (False, True):
                with self.subTest(mode=mode, kill_fails=kill_fails):
                    session, _script, _native, device, _logs, connected, failures, _warnings = self._hook_setup()
                    session._config = SessionConfig(**{
                        {"spawn": "spawn_package", "name": "attach_name", "pid": "attach_pid"}[mode]:
                        42 if mode == "pid" else "dev.example",
                        "validated_hooks": HooksLoadResult([], []),
                    })
                    entered, release = threading.Event(), threading.Event()
                    resumed = []

                    def attach(_target):
                        entered.set()
                        release.wait(2)
                        raise RuntimeError("attach failed after cancellation")

                    def kill(pid):
                        device.killed.append(pid)
                        if kill_fails:
                            raise RuntimeError("kill unavailable")

                    device.attach = attach
                    device.kill = kill
                    device.resume = resumed.append
                    fake_frida = SimpleNamespace(get_device=lambda *_a, **_k: device)
                    with patch.dict(sys.modules, {"frida": fake_frida}):
                        session.connect("device-1")
                        try:
                            self.assertTrue(entered.wait(2))
                            session.cleanup()
                        finally:
                            release.set()
                            session._connect_thread.join(2)
                    self.assertFalse(session._connect_thread.is_alive())
                    self.assertEqual(device.killed, [42] if mode == "spawn" else [])
                    self.assertEqual(resumed, [42] if mode == "spawn" and kill_fails else [])
                    self.assertEqual(connected, [])
                    self.assertEqual(failures, [])

    def test_cancellation_during_device_lookup_or_spawn_stops_startup(self):
        for boundary in ("device", "spawn"):
            with self.subTest(boundary=boundary):
                session, _script, _native, device, _logs, connected, failures, _warnings = self._hook_setup()
                entered, release = threading.Event(), threading.Event()
                calls = []

                def wait():
                    entered.set()
                    release.wait(2)

                def get_device(*_args, **_kwargs):
                    if boundary == "device":
                        wait()
                    return device

                def spawn(_args):
                    calls.append("spawn")
                    wait()
                    return 42

                device.spawn = spawn
                device.attach = lambda _pid: calls.append("attach")
                with patch.dict(sys.modules, {"frida": SimpleNamespace(get_device=get_device)}):
                    session.connect("device-1")
                    try:
                        self.assertTrue(entered.wait(2))
                        session.cleanup()
                    finally:
                        release.set()
                        session._connect_thread.join(2)
                self.assertFalse(session._connect_thread.is_alive())
                self.assertEqual(calls, ["spawn"] if boundary == "spawn" else [])
                self.assertEqual(device.killed, [42] if boundary == "spawn" else [])
                self.assertEqual(connected, [])
                self.assertEqual(failures, [])

    def test_old_detach_cannot_clear_replacement_connection(self):
        setup = self._hook_setup()
        session, _script, native, _device, logs, *_rest = setup
        self._run_hook_setup(setup, {
            "installed": 1, "installedIndices": [0], "skipped": [], "failed": [],
        })
        old_detach = native.callbacks["detached"]
        session.cleanup()
        replacement_script = _FakeHookScript()
        replacement_native = _FakeHookNativeSession(replacement_script)
        replacement_device = _FakeHookDevice(replacement_native)
        setup = (session, replacement_script, replacement_native, replacement_device, *setup[4:])
        self._run_hook_setup(setup, {
            "installed": 1, "installedIndices": [0], "skipped": [], "failed": [],
        })
        disconnected = []
        session.disconnected_cb = lambda: disconnected.append(True)
        before = len(logs)
        old_detach("application-requested", None)
        self.assertTrue(session.is_ready())
        self.assertIs(session._session, replacement_native)
        self.assertIs(session._script, replacement_script)
        self.assertEqual(session.hook_registration_count, 1)
        self.assertEqual(disconnected, [])
        self.assertEqual(len(logs), before)
        replacement_native.callbacks["detached"]("process-terminated", None)
        self.assertFalse(session.is_ready())
        self.assertEqual(disconnected, [True])

    def test_cleanup_after_resumed_spawn_does_not_kill_app(self):
        setup = self._hook_setup()
        session, _script, native, device, *_rest = setup
        self._run_hook_setup(setup, {
            "installed": 1, "installedIndices": [0], "skipped": [], "failed": [],
        })
        session.cleanup()
        self.assertTrue(native.detached)
        self.assertTrue(device.resumed.is_set())
        self.assertEqual(device.killed, [])

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
        failures = []
        session.connection_failed_cb = lambda stage, error: failures.append((stage, error))

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
        self.assertEqual(failures, [])


class _FakeFridaSession:
    def __init__(self):
        self.detached = False
        self.callbacks = {}

    def on(self, event_name, callback):
        self.callbacks[event_name] = callback

    def detach(self):
        self.detached = True


class _FakeHookScript:
    def __init__(self):
        self.callbacks = {}
        self.proxy_called = threading.Event()
        self.exports_sync = SimpleNamespace(
            proxy=self._proxy,
            get_sdk_int=lambda: 31,
            interceptoff=lambda: None,
        )

    def _proxy(self, _hooks):
        self.proxy_called.set()
        return {"pending": True}

    def on(self, name, callback):
        self.callbacks[name] = callback

    def load(self):
        pass

    def unload(self):
        pass

    def emit_report(self, report):
        self.callbacks["message"]({
            "type": "send", "payload": {"noxenEvent": "hook_report", "report": report},
        }, None)


class _FakeHookNativeSession(_FakeFridaSession):
    def __init__(self, script):
        super().__init__()
        self.script = script

    def create_script(self, _code):
        return self.script


class _FakeHookDevice:
    def __init__(self, native_session):
        self.native_session = native_session
        self.resumed = threading.Event()
        self.killed = []

    def spawn(self, _packages):
        return 42

    def attach(self, _target):
        return self.native_session

    def resume(self, _pid):
        self.resumed.set()

    def kill(self, pid):
        self.killed.append(pid)


if __name__ == "__main__":
    unittest.main()
