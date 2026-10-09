import asyncio
import os
import tempfile
import threading
import unittest
from types import SimpleNamespace

from textual.widgets import Button, Input, Label, Select

from noxen.app import NoxenApp
from noxen.logging_ui import log_error


class ServerNotRunningError(Exception):
    pass


class _DelayedFailingSession:
    def __init__(self, app, release: threading.Event, finished: threading.Event):
        self.app = app
        self.release = release
        self.finished = finished
        self.api_level_cb = None
        self.connected_cb = None
        self.connection_failed_cb = None
        self.disconnected_cb = None

    def connect(self, _device_id):
        def fail():
            self.release.wait(timeout=2)
            self.app._log_entries.append(log_error(
                "Connection failed: unable to connect to remote frida-server", "frida"
            ))
            self.connection_failed_cb(
                "device", ServerNotRunningError("unable to connect to remote frida-server")
            )
            self.finished.set()

        threading.Thread(target=fail, daemon=True).start()

    def cleanup(self):
        pass


class _DelayedSuccessfulSession:
    def __init__(self, release: threading.Event, finished: threading.Event):
        self.release = release
        self.finished = finished
        self.api_level_cb = None
        self.connected_cb = None
        self.connection_failed_cb = None
        self.disconnected_cb = None

    def connect(self, _device_id):
        def succeed():
            self.release.wait(timeout=2)
            self.api_level_cb(35)
            self.connected_cb()
            self.finished.set()

        threading.Thread(target=succeed, daemon=True).start()

    def get_app_info(self):
        return {
            "identity": {"package": "dev.example"},
            "build": {},
            "signing": {},
            "permissions": [],
            "components": [],
        }

    def is_ready(self):
        return True

    def cleanup(self):
        pass


class ConnectionFeedbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_hook_config_blocks_connect_without_cleaning_current_session(self):
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                hook_path = os.path.join(tmp, "invalid-hooks.json")
                with open(hook_path, "w", encoding="utf-8") as file:
                    file.write('{"clazz": "Example"}')
                args = SimpleNamespace(
                    project=None,
                    new_project=os.path.join(tmp, "invalid-config.noxen"),
                    skip_device_scan=True,
                )
                app = NoxenApp(args)
                cleaned = []
                current_session = SimpleNamespace(cleanup=lambda: cleaned.append(True))

                async with app.run_test(size=(120, 40)) as pilot:
                    app.notify = lambda *_args, **_kwargs: None
                    app._populate_target_apps = lambda: None
                    app._home_devices = [SimpleNamespace(id="device-1")]
                    app.frida_session = current_session

                    device = app.query_one("#home_device", Select)
                    device.set_options([("Android", "device-1")])
                    device.value = "device-1"
                    target = app.query_one("#home_target_select", Select)
                    target.set_options([("Example", "dev.example")])
                    target.value = "dev.example"
                    app.query_one("#home_hooks_path", Input).value = hook_path
                    await pilot.pause()

                    app._try_connect()
                    await pilot.pause()

                    self.assertIs(app.frida_session, current_session)
                    self.assertEqual(cleaned, [])
                    self.assertIn("top-level value must be a JSON array", str(
                        app.query_one("#home_error", Label).render()
                    ))
                    self.assertFalse(app.query_one("#home_btn", Button).disabled)
            finally:
                os.chdir(cwd)

    async def test_failed_connection_stays_home_and_shows_feedback(self):
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                args = SimpleNamespace(
                    project=None,
                    new_project=os.path.join(tmp, "feedback.noxen"),
                    skip_device_scan=True,
                )
                app = NoxenApp(args)
                notices = []
                release = threading.Event()
                finished = threading.Event()

                async with app.run_test(size=(120, 40)) as pilot:
                    app.notify = lambda message, **kwargs: notices.append((message, kwargs))
                    app._populate_target_apps = lambda: None
                    app._home_devices = [SimpleNamespace(id="device-1")]

                    device = app.query_one("#home_device", Select)
                    device.set_options([("Android", "device-1")])
                    device.value = "device-1"
                    target = app.query_one("#home_target_select", Select)
                    target.set_options([("Example", "dev.example")])
                    target.value = "dev.example"
                    await pilot.pause()

                    def init_session(config):
                        app._session_config = config
                        app.frida_session = _DelayedFailingSession(app, release, finished)

                    app._init_session = init_session
                    app._try_connect()
                    await pilot.pause()

                    self.assertEqual(app.query_one("#main_tabs").active, "tab_home")
                    self.assertEqual(app._connection_state, "connecting")
                    self.assertTrue(app.query_one("#home_btn", Button).disabled)
                    self.assertEqual(str(app.query_one("#home_btn", Button).label), "Connecting…")
                    self.assertFalse(app.query_one("#session_bar").has_class("connected"))
                    self.assertTrue(app.query_one("#session_bar").has_class("connecting"))
                    self.assertEqual(app.query_one("#session_bar").styles.background.hex, "#65B8E8")

                    release.set()
                    for _ in range(100):
                        if finished.is_set():
                            break
                        await asyncio.sleep(0.01)
                    self.assertTrue(finished.is_set())
                    await pilot.pause()

                    message = "Connection failed. Frida server is not running or cannot be reached."
                    self.assertEqual(app.query_one("#main_tabs").active, "tab_home")
                    self.assertEqual(app._connection_state, "disconnected")
                    self.assertIsNone(app.frida_session)
                    self.assertFalse(app.query_one("#home_btn", Button).disabled)
                    self.assertEqual(str(app.query_one("#home_btn", Button).label), "Connect")
                    self.assertTrue(app.query_one("#home_disconnect", Button).disabled)
                    self.assertEqual(str(app.query_one("#session_info", Label).render()), "Not connected")
                    self.assertFalse(app.query_one("#session_bar").has_class("connecting"))
                    self.assertFalse(app.query_one("#session_bar").has_class("connected"))
                    self.assertTrue(app.query_one("#session_bar").has_class("connection-error"))
                    self.assertEqual(app.query_one("#session_bar").styles.background.hex, "#D76470")
                    failed_generation = app._connection_generation
                    app._connection_generation += 1
                    app._clear_session_error_state(failed_generation)
                    self.assertTrue(app.query_one("#session_bar").has_class("connection-error"))
                    app._clear_session_error_state()
                    await pilot.pause()
                    self.assertFalse(app.query_one("#session_bar").has_class("connection-error"))
                    self.assertEqual(app.query_one("#session_bar").styles.background.hex, "#1B2723")
                    self.assertIn(message, str(app.query_one("#home_error", Label).render()))
                    self.assertEqual(notices, [(message, {"severity": "error", "timeout": 6})])
                    self.assertIn("unable to connect to remote frida-server", app._log_entries[-1])
            finally:
                os.chdir(cwd)

    async def test_successful_connection_opens_intercept_only_when_ready(self):
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                args = SimpleNamespace(
                    project=None,
                    new_project=os.path.join(tmp, "success.noxen"),
                    skip_device_scan=True,
                )
                app = NoxenApp(args)
                release = threading.Event()
                finished = threading.Event()

                async with app.run_test(size=(120, 40)) as pilot:
                    app._populate_target_apps = lambda: None
                    app._fetch_app_info_worker = lambda: None
                    app._home_devices = [SimpleNamespace(id="device-1")]

                    device = app.query_one("#home_device", Select)
                    device.set_options([("Android", "device-1")])
                    device.value = "device-1"
                    target = app.query_one("#home_target_select", Select)
                    target.set_options([("Example", "dev.example")])
                    target.value = "dev.example"
                    await pilot.pause()

                    def init_session(config):
                        app._session_config = config
                        app.frida_session = _DelayedSuccessfulSession(release, finished)

                    app._init_session = init_session
                    app._try_connect()
                    await pilot.pause()

                    self.assertEqual(app.query_one("#main_tabs").active, "tab_home")
                    self.assertEqual(app._connection_state, "connecting")
                    self.assertTrue(app.query_one("#session_bar").has_class("connecting"))

                    release.set()
                    for _ in range(100):
                        if finished.is_set():
                            break
                        await asyncio.sleep(0.01)
                    self.assertTrue(finished.is_set())
                    await pilot.pause()

                    self.assertEqual(app.query_one("#main_tabs").active, "tab_intercept")
                    self.assertEqual(app._connection_state, "connected")
                    self.assertFalse(app.query_one("#session_bar").has_class("connecting"))
                    self.assertTrue(app.query_one("#session_bar").has_class("connected"))
                    self.assertTrue(app.query_one("#home_btn", Button).disabled)
                    self.assertFalse(app.query_one("#home_disconnect", Button).disabled)
                    self.assertEqual(
                        str(app.query_one("#session_info", Label).render()),
                        "dev.example  ·  device-1  ·  API 35",
                    )
            finally:
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
