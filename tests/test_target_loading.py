import asyncio
import sys
import threading
from types import SimpleNamespace
from unittest.mock import patch

from textual.widgets import Label, Select

from noxen.app import NoxenApp
from noxen.textual_compat import is_select_empty
from tests.ui_test_case import IsolatedAppTestCase


class Devices(list):
    def get_device(self, device_id, timeout=0):
        return next(device for device in self if device.id == device_id)


def target_values(app):
    return [value for _, value in app.query_one("#home_target_select", Select)._options
            if isinstance(value, str)]


class TargetLoadingTests(IsolatedAppTestCase):
    async def test_device_refresh_preserves_selection_and_loads_targets_once(self):
        calls = []
        def apps(device_id):
            calls.append(device_id)
            return [SimpleNamespace(identifier=device_id + ".package")]
        devices = Devices([
            SimpleNamespace(id=key, name=key, type="usb",
                            enumerate_applications=lambda key=key: apps(key))
            for key in ("A", "B")
        ])
        app = NoxenApp(SimpleNamespace(project=None, skip_device_scan=True,
                                      new_project=str(self.settings_path.parent / "refresh")))
        try:
            with patch.dict(sys.modules, {"frida": SimpleNamespace()}), patch(
                "noxen.app.scan_devices", return_value=devices,
            ):
                async with app.run_test(size=(110, 36)) as pilot:
                    app._populate_home_devices()
                    await app.workers.wait_for_complete()
                    await pilot.pause()
                    select = app.query_one("#home_device", Select)
                    select.value = "B"
                    await pilot.pause()
                    await app.workers.wait_for_complete()
                    calls.clear()
                    app._populate_home_devices()
                    await app.workers.wait_for_complete()
                    await pilot.pause()
                    self.assertEqual(select.value, "B")
                    self.assertEqual(target_values(app), ["B.package"])
                    self.assertEqual(calls, ["B"])
                    # Changing mode during a device rescan cannot use its old
                    # context to repopulate targets before discovery completes.
                    with patch.object(app, "_populate_home_devices_worker"):
                        app._populate_home_devices()
                        app.query_one("#home_mode", Select).value = "p"
                        await pilot.pause()
                        self.assertEqual(target_values(app), [])
                        self.assertEqual(calls, ["B"])
                        self.assertIsNone(app._target_scan_context)
        finally:
            app.db.close()

    async def test_only_latest_target_request_can_update_results_or_errors(self):
        for change in ("mode", "device", "reload", "device_back", "mode_back"):
            for old_fails in (False, True):
                with self.subTest(change=change, old_fails=old_fails):
                    await self.check_race(change, old_fails)

    async def check_race(self, change, old_fails, new_fails=False):
        entered, release = threading.Event(), threading.Event()
        calls = 0

        def new_apps():
            if new_fails:
                raise RuntimeError("latest failure")
            return [SimpleNamespace(identifier="new.package")]

        def old_apps():
            nonlocal calls
            calls += 1
            if calls == 1:
                entered.set()
                if not release.wait(5):
                    raise RuntimeError("test barrier timed out")
                if old_fails:
                    raise RuntimeError("old failure")
                return [SimpleNamespace(identifier="old.package")]
            return new_apps()

        devices = Devices([
            SimpleNamespace(id="A", enumerate_applications=old_apps,
                            enumerate_processes=lambda: [SimpleNamespace(name="Process", pid=123)]),
            SimpleNamespace(id="B", enumerate_applications=new_apps),
        ])
        name = f"{change}-{old_fails}-{new_fails}"
        app = NoxenApp(SimpleNamespace(project=None, skip_device_scan=True,
                                      new_project=str(self.settings_path.parent / name)))
        populate = app._populate_target_apps
        app._populate_target_apps = lambda: None
        try:
            with patch.dict(sys.modules, {"frida": SimpleNamespace()}):
                async with app.run_test(size=(110, 36)) as pilot:
                    app._home_devices = devices
                    select = app.query_one("#home_device", Select)
                    select.set_options([("A", "A"), ("B", "B")])
                    select.value = "A"
                    await pilot.pause()
                    app._populate_target_apps = populate
                    populate()
                    self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                    target = app.query_one("#home_target_select", Select)
                    self.assertTrue(target.disabled)
                    self.assertTrue(is_select_empty(target.value))

                    if change.startswith("mode"):
                        app.query_one("#home_mode", Select).value = "p"
                        expected = ["123"]
                    elif change.startswith("device"):
                        select.value = "B"
                        expected = ["new.package"]
                    else:
                        populate()
                        expected = ["new.package"]
                    await pilot.pause()
                    if change == "device_back":
                        select.value = "A"
                        expected = ["new.package"]
                    elif change == "mode_back":
                        app.query_one("#home_mode", Select).value = "f"
                        expected = ["new.package"]
                    if new_fails:
                        expected = []
                    for _ in range(100):
                        await asyncio.sleep(.01)
                        if (target_values(app) == expected
                                and "Loading" not in str(app.query_one("#home_error", Label).render())):
                            break
                    self.assertEqual(target_values(app), expected)
                    release.set()
                    await app.workers.wait_for_complete()
                    await pilot.pause()
                    self.assertEqual(target_values(app), expected)
                    error = str(app.query_one("#home_error", Label).render())
                    self.assertEqual(error, "Apps: latest failure" if new_fails else "")
                    self.assertEqual(target.disabled, new_fails)
        finally:
            release.set()
            app.db.close()

    async def test_old_success_cannot_replace_a_newer_failure(self):
        await self.check_race("reload", False, new_fails=True)

    async def test_disappearing_device_clears_targets_and_invalidates_pending_results(self):
        app = NoxenApp(SimpleNamespace(project=None, skip_device_scan=True,
                                      new_project=str(self.settings_path.parent / "disappear")))
        populate = app._populate_target_apps
        app._populate_target_apps = lambda: None
        try:
            async with app.run_test(size=(110, 36)) as pilot:
                app._home_devices = Devices([SimpleNamespace(id="A")])
                device = app.query_one("#home_device", Select)
                device.set_options([("A", "A")])
                device.value = "A"
                target = app.query_one("#home_target_select", Select)
                target.set_options([("Old", "old.package")])
                target.value = "old.package"
                await pilot.pause()
                app._populate_target_apps = populate
                app._home_devices = Devices([])
                device.set_options([])
                await pilot.pause()
                self.assertEqual(target_values(app), [])
                self.assertTrue(is_select_empty(target.value))
                self.assertTrue(target.disabled)
                self.assertIsNone(app._target_scan_context)
        finally:
            app.db.close()

    async def test_invalid_or_stale_target_cannot_disconnect_existing_session(self):
        app = NoxenApp(SimpleNamespace(project=None, skip_device_scan=True,
                                      new_project=str(self.settings_path.parent / "validation")))
        app._populate_target_apps = lambda: None
        cleaned = []
        session = SimpleNamespace(cleanup=lambda: cleaned.append(True))
        try:
            async with app.run_test(size=(110, 36)) as pilot:
                app._home_devices = Devices([SimpleNamespace(id="A")])
                device = app.query_one("#home_device", Select)
                device.set_options([("A", "A")])
                device.value = "A"
                mode = app.query_one("#home_mode", Select)
                mode.value = "p"
                await pilot.pause()
                app.frida_session = session
                target = app.query_one("#home_target_select", Select)
                app._target_scan_context = ("A", "p")
                for value in ("old.package", "0", "-1", "1.5", "1" * 5000):
                    with self.subTest(value=value[:20]):
                        target.set_options([("Invalid", value)])
                        target.value = value
                        app._try_connect()
                        self.assertIs(app.frida_session, session)
                        self.assertEqual(cleaned, [])
                        self.assertIn("valid positive PID", str(app.query_one("#home_error", Label).render()))
                target.set_options([("PID", "123")])
                target.value = "123"
                app._target_scan_context = ("A", "f")
                app._try_connect()
                self.assertEqual(cleaned, [])
                self.assertIn("Refresh targets", str(app.query_one("#home_error", Label).render()))
                app._target_scan_context = ("A", "p")
                target.disabled = True
                app._try_connect()
                self.assertEqual(cleaned, [])
                target.disabled = False
                with patch.object(app, "_init_session") as init, patch.object(app, "on_device_selected"):
                    app._try_connect()
                self.assertEqual(init.call_args.args[0].attach_pid, 123)
                self.assertEqual(cleaned, [True])
                app.frida_session = None
        finally:
            app.frida_session = None
            app.db.close()
