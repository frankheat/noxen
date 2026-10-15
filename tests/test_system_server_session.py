import sys
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from noxen.agent_loader import ScriptLoadResult
from noxen.system_server_session import SystemServerConfig, SystemServerSession, format_system_server_log


class FakeExports:
    def __init__(self):
        self.calls = []
        self.called = threading.Event()

    def holdstart(self, hold):
        self.calls.append(("holdstart", hold))
        self.called.set()

    def holdend(self, hold_id, pid):
        self.calls.append(("holdend", hold_id, pid))

    def clear(self):
        self.calls.append(("clear",))


class LifecycleScript:
    def __init__(self):
        self.callbacks = {}
        self.exports_sync = FakeExports()
        self.exports_sync.init = lambda _config: None
        self.exports_sync.status = lambda: {"installedOverloads": 1}

    def on(self, event, callback):
        self.callbacks[event] = callback

    def load(self):
        pass


class LifecycleNativeSession:
    def __init__(self):
        self.script = LifecycleScript()
        self.callbacks = {}
        self.is_detached = False
        self.create_script = lambda _code: self.script

    def on(self, event, callback):
        self.callbacks[event] = callback

    def detach(self):
        self.is_detached = True
        if "detached" in self.callbacks:
            self.callbacks["detached"]("application-requested", None)


class SystemServerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.logs = []
        self.owner = SystemServerSession(SystemServerConfig(), self.logs.append)
        self.sessions = {name: LifecycleNativeSession() for name in ("old", "new")}
        self.workers = []
        self.releases = []
        self.devices_requested = []

        def get_device(device_id, timeout=5):
            self.devices_requested.append(device_id)
            return SimpleNamespace(
                enumerate_processes=lambda: [SimpleNamespace(name="system_server", pid=1000)],
                attach=lambda _pid: self.sessions[device_id],
            )

        self.fake_frida = SimpleNamespace(get_device=get_device)
        self.module_patch = patch.dict(sys.modules, {"frida": self.fake_frida})
        self.loader_patch = patch("noxen.system_server_session.load_system_server_script",
                                  return_value=ScriptLoadResult("agent", []))
        self.module_patch.start()
        self.loader_patch.start()

    def tearDown(self):
        for release in self.releases:
            release.set()
        for worker in self.workers:
            worker.join(2)
            self.assertFalse(worker.is_alive(), "Connection worker did not stop")
        self.owner.cleanup()
        self.loader_patch.stop()
        self.module_patch.stop()

    def start(self, device):
        self.owner.connect(device)
        worker = self.owner._connect_thread
        self.workers.append(worker)
        return worker

    def finish(self, device):
        worker = self.start(device)
        worker.join(2)
        self.assertFalse(worker.is_alive())

    def pause(self, native, attribute, *, error=False):
        entered, release = threading.Event(), threading.Event()
        self.releases.append(release)

        def blocked(*_args):
            entered.set()
            if not release.wait(2):
                raise RuntimeError("Test barrier timed out")
            if error:
                raise RuntimeError("Old connection failed")
            return {"installedOverloads": 1}

        setattr(native.script.exports_sync, attribute, blocked)
        return entered, release

    def assert_new_ready(self):
        self.assertIs(self.owner._session, self.sessions["new"])
        self.assertIs(self.owner._script, self.sessions["new"].script)
        self.assertTrue(self.owner._ready.is_set())
        self.assertFalse(self.sessions["new"].is_detached)

    def test_delayed_detach_from_old_session_cannot_clear_new_session(self):
        self.finish("old")
        old_callback = self.sessions["old"].callbacks["detached"]
        self.finish("new")
        old_callback("process-terminated", None)
        self.assert_new_ready()

    def test_old_initialization_failure_cannot_clean_up_new_connection(self):
        entered, release = self.pause(self.sessions["old"], "init", error=True)
        worker = self.start("old")
        self.assertTrue(entered.wait(1))
        self.finish("new")
        self.owner.hold_start({"holdId": "new-hold", "pid": 42})
        release.set()
        worker.join(2)
        self.assert_new_ready()
        self.assertIn("new-hold", self.owner._active_holds)
        self.assertTrue(self.sessions["old"].is_detached)
        self.assertFalse(any("Old connection failed" in line for line in self.logs))

    def test_detach_before_ready_cannot_be_published_as_ready(self):
        native = self.sessions["old"]

        def status_then_detach():
            native.detach()
            return {"installedOverloads": 1}

        native.script.exports_sync.status = status_then_detach
        self.finish("old")
        self.assertFalse(self.owner._ready.is_set())
        self.assertIsNone(self.owner._script)
        self.assertIsNone(self.owner._session)

    def test_partial_initialization_failure_detaches_local_resources(self):
        for phase in ("create_script", "load", "init", "status"):
            with self.subTest(phase=phase):
                native = LifecycleNativeSession()
                self.sessions["old"] = native

                def fail(*_args):
                    raise RuntimeError("Initialization failed")

                target = native if phase == "create_script" else native.script if phase == "load" else native.script.exports_sync
                setattr(target, phase, fail)
                self.finish("old")
                self.assertTrue(native.is_detached)
                self.assertFalse(self.owner._ready.is_set())
                self.assertIsNone(self.owner._script)

    def test_queued_rpc_cannot_be_redirected_to_replacement_script(self):
        self.finish("old")
        with patch("noxen.system_server_session.threading.Thread") as thread:
            self.owner.hold_start({"holdId": "old-hold", "pid": 42})
            task = thread.call_args.kwargs
            self.owner.hold_end("old-hold", 42)
            end_task = thread.call_args.kwargs
        self.finish("new")
        task["target"](*task["args"])
        end_task["target"](*end_task["args"])
        calls = self.sessions["new"].script.exports_sync.calls
        self.assertEqual(calls, [])

    def test_cleanup_during_initialization_cannot_resurrect_connection(self):
        entered, release = self.pause(self.sessions["old"], "status")
        worker = self.start("old")
        self.assertTrue(entered.wait(1))
        self.owner.cleanup()
        release.set()
        worker.join(2)
        self.assertFalse(self.owner._ready.is_set())
        self.assertIsNone(self.owner._script)
        self.assertTrue(self.sessions["old"].is_detached)

    def test_same_device_can_reconnect_while_cancelled_worker_is_still_running(self):
        entered, release = self.pause(self.sessions["old"], "init", error=True)
        old_worker = self.start("old")
        self.assertTrue(entered.wait(1))
        self.owner.cleanup()
        replacement = LifecycleNativeSession()
        self.sessions["old"] = replacement
        self.finish("old")
        release.set()
        old_worker.join(2)
        self.assertIs(self.owner._session, replacement)
        self.assertIs(self.owner._script, replacement.script)
        self.assertTrue(self.owner._ready.is_set())
        self.assertFalse(replacement.is_detached)

    def test_cancellation_at_each_startup_stage_does_not_touch_replacement(self):
        for phase in ("device", "attach", "create_script", "load"):
            with self.subTest(phase=phase):
                old, new = LifecycleNativeSession(), LifecycleNativeSession()
                self.sessions.update(old=old, new=new)
                entered, release = threading.Event(), threading.Event()
                self.releases.append(release)
                original_get_device = self.fake_frida.get_device

                def blocked(result):
                    entered.set()
                    if not release.wait(2):
                        raise RuntimeError("Test barrier timed out")
                    return result

                def get_device(device_id, timeout=5):
                    device = original_get_device(device_id, timeout)
                    if device_id == "old":
                        if phase == "device":
                            return blocked(device)
                        if phase == "attach":
                            device.attach = lambda _pid: blocked(old)
                    return device

                if phase == "create_script":
                    old.create_script = lambda _code: blocked(old.script)
                if phase == "load":
                    old.script.load = lambda: blocked(None)
                with patch.object(self.fake_frida, "get_device", get_device):
                    worker = self.start("old")
                    self.assertTrue(entered.wait(1))
                    self.finish("new")
                    release.set()
                    worker.join(2)
                self.assert_new_ready()
                if phase != "device":
                    self.assertTrue(old.is_detached)

    def test_initial_worker_keeps_its_original_device_id(self):
        with patch("noxen.system_server_session.threading.Thread") as thread:
            self.owner.connect("old")
            task = thread.call_args.kwargs
        # The worker must use its captured argument, not mutable owner state.
        self.owner._device_id = "new"
        task["target"](*task["args"])
        self.assertEqual(self.devices_requested, ["old"])
        self.assertIs(self.owner._session, self.sessions["old"])

    def test_duplicate_connect_is_ignored_during_startup_and_when_ready(self):
        entered, release = self.pause(self.sessions["old"], "init")
        worker = self.start("old")
        self.assertTrue(entered.wait(1))
        self.owner.connect("old")
        self.assertIs(self.owner._connect_thread, worker)
        release.set()
        worker.join(2)
        self.owner.connect("old")
        self.assertIs(self.owner._connect_thread, worker)
        self.assertEqual(self.devices_requested, ["old"])

    def test_superseded_worker_does_not_even_request_a_device(self):
        with patch("noxen.system_server_session.threading.Thread") as thread:
            self.owner.connect("old")
            first = thread.call_args.kwargs
            self.owner.connect("new")
            second = thread.call_args.kwargs
        first["target"](*first["args"])
        self.assertEqual(self.devices_requested, [])
        second["target"](*second["args"])
        self.assertEqual(self.devices_requested, ["new"])
        self.assert_new_ready()

    def test_current_detach_clears_ready_and_allows_retry(self):
        self.finish("old")
        self.sessions["old"].detach()
        self.assertFalse(self.owner._ready.is_set())
        replacement = LifecycleNativeSession()
        self.sessions["old"] = replacement
        self.finish("old")
        self.assertIs(self.owner._session, replacement)
        self.assertTrue(self.owner._ready.is_set())

    def test_already_detached_session_is_not_initialized(self):
        self.sessions["old"].is_detached = True
        with patch.object(self.sessions["old"].script.exports_sync, "init") as init:
            self.finish("old")
        init.assert_not_called()
        self.assertFalse(self.owner._ready.is_set())

    def test_late_messages_from_previous_script_are_ignored(self):
        self.finish("old")
        callback = self.sessions["old"].script.callbacks["message"]
        self.finish("new")
        count = len(self.logs)
        callback({"type": "error", "description": "old script error"}, None)
        self.assertEqual(len(self.logs), count)
        self.assert_new_ready()

    def test_cleanup_failure_still_detaches_and_does_not_escape(self):
        self.finish("old")

        def fail():
            raise RuntimeError("Script destroyed")

        self.sessions["old"].script.exports_sync.clear = fail
        self.owner.cleanup()
        self.assertTrue(self.sessions["old"].is_detached)
        self.assertFalse(self.owner._ready.is_set())
        self.owner.cleanup()

    def test_late_cleanup_cannot_detach_the_replacement(self):
        self.finish("old")
        entered, release = threading.Event(), threading.Event()
        self.releases.append(release)

        def blocked_clear():
            entered.set()
            if not release.wait(2):
                raise RuntimeError("Test barrier timed out")

        self.sessions["old"].script.exports_sync.clear = blocked_clear
        cleaner = threading.Thread(target=self.owner.cleanup)
        self.workers.append(cleaner)
        cleaner.start()
        self.assertTrue(entered.wait(1))
        self.finish("new")
        release.set()
        cleaner.join(2)
        self.assert_new_ready()

    def test_stale_rpc_failure_does_not_report_a_new_connection_failure(self):
        self.finish("old")
        script = self.owner._script
        generation = self.owner._generation
        entered, release = threading.Event(), threading.Event()
        self.releases.append(release)

        def fail(_hold):
            entered.set()
            if not release.wait(2):
                raise RuntimeError("Test barrier timed out")
            raise RuntimeError("Stale RPC failure")

        script.exports_sync.holdstart = fail
        worker = threading.Thread(target=self.owner._call_script,
                                  args=(generation, script, "holdstart", ({"holdId": "h1"},)))
        self.workers.append(worker)
        worker.start()
        self.assertTrue(entered.wait(1))
        self.finish("new")
        release.set()
        worker.join(2)
        self.assertFalse(any("Stale RPC failure" in line for line in self.logs))
        self.assert_new_ready()


class SystemServerSessionTests(unittest.TestCase):
    def test_default_hold_window_is_two_minutes(self):
        self.assertEqual(SystemServerConfig().max_hold_ms, 120000)

    def test_hold_start_is_synced_after_script_becomes_ready(self):
        session = SystemServerSession(SystemServerConfig(max_hold_ms=1234), log_cb=lambda _text: None)
        exports = FakeExports()
        session.hold_start({"holdId": "h1", "pid": 42})

        with session._lock:
            session._script = SimpleNamespace(exports_sync=exports)
            session._ready.set()

        session._sync_active_holds()

        self.assertTrue(exports.called.wait(1))
        self.assertEqual(exports.calls, [("holdstart", {"holdId": "h1", "pid": 42, "timeoutMs": 1234})])

    def test_hold_end_removes_pending_hold(self):
        session = SystemServerSession(SystemServerConfig(), log_cb=lambda _text: None)
        session.hold_start({"holdId": "h1", "pid": 42})

        session.hold_end("h1", 42)

        self.assertEqual(session._active_holds, {})

    def test_find_system_server_pid(self):
        device = SimpleNamespace(enumerate_processes=lambda: [
            SimpleNamespace(name="app", pid=1),
            SimpleNamespace(name="system_server", pid=1000),
        ])

        self.assertEqual(SystemServerSession._find_system_server_pid(device), 1000)

    def test_connect_cleans_up_previous_device(self):
        session = SystemServerSession(SystemServerConfig(), log_cb=lambda _text: None)
        session._device_id = "old"
        old_script, old_session = object(), object()
        session._script, session._session = old_script, old_session
        session._active_holds["old-hold"] = {"pid": 42}
        with patch.object(session, "_cleanup_resources_async") as cleanup:
            with patch("threading.Thread") as thread:
                thread.return_value = SimpleNamespace(start=lambda: None)
                session.connect("new")

        cleanup.assert_called_once_with(old_script, old_session)
        self.assertEqual(session._active_holds, {})
        self.assertIsNone(session._script)
        self.assertEqual(thread.call_args.kwargs["args"], (1, "new"))

    def test_log_status_reports_installed_hooks(self):
        logs = []
        session = SystemServerSession(SystemServerConfig(), log_cb=logs.append)

        session._log_status({
            "installedOverloads": 2,
            "missingHooks": 1,
            "failedHooks": 1,
            "hooks": [
                {"className": "A", "methodName": "ok", "installed": 2, "status": "installed"},
                {"className": "B", "methodName": "bad", "installed": 0, "status": "error", "error": "boom"},
            ],
        })

        joined = "\n".join(logs)
        self.assertIn("Input ANR bypass enabled", joined)
        self.assertIn("2 overloads, 1 missing, 1 failed", joined)
        self.assertIn("A.ok: 2 overload", joined)
        self.assertIn("B.bad: boom", joined)

    def test_log_status_warns_when_no_hooks_are_installed(self):
        logs = []
        session = SystemServerSession(SystemServerConfig(), log_cb=logs.append)

        session._log_status({"installedOverloads": 0})

        self.assertEqual(
            logs,
            [
                "[dim]input-anr    [/dim] [yellow]WARN [/yellow] "
                "Input ANR bypass is enabled, but no supported system_server hooks were installed"
            ],
        )

    def test_format_system_server_log_uses_consistent_levels(self):
        self.assertEqual(
            format_system_server_log({
                "noxenEvent": "system_server_log",
                "level": "success",
                "message": "Hooked A.b",
            }),
            "[dim]system_server[/dim] [#26a368]OK   [/#26a368] Hooked A.b",
        )
        self.assertEqual(
            format_system_server_log({
                "noxenEvent": "system_server_log",
                "level": "warning",
                "message": "Skipped A.b",
            }),
            "[dim]system_server[/dim] [yellow]WARN [/yellow] Skipped A.b",
        )


if __name__ == "__main__":
    unittest.main()
