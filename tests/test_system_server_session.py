import unittest
from types import SimpleNamespace
from unittest.mock import patch

from noxen.system_server_session import SystemServerConfig, SystemServerSession, format_system_server_log


class FakeExports:
    def __init__(self):
        self.calls = []

    def holdstart(self, hold):
        self.calls.append(("holdstart", hold))

    def holdend(self, hold_id, pid):
        self.calls.append(("holdend", hold_id, pid))


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
        with patch.object(session, "cleanup") as cleanup:
            with patch("threading.Thread") as thread:
                thread.return_value = SimpleNamespace(start=lambda: None)
                session.connect("new")

        cleanup.assert_called_once()

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
