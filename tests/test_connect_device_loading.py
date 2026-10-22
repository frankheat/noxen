import os
import sys
import tempfile
import unittest
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import patch

from tests.ui_test_case import IsolatedAppTestCase

from noxen.app import NoxenApp
from noxen.frida_devices import enumerate_preferred_devices
from noxen.textual_compat import SELECT_EMPTY


def project_args(path: str) -> SimpleNamespace:
    return SimpleNamespace(
        project=None,
        new_project=path,
    )


class FakeLabel:
    def __init__(self):
        self.text = None

    def update(self, text):
        self.text = text


class FakeSelect:
    def __init__(self):
        self.options = []
        self.value = None

    def set_options(self, options):
        self.options = options

    def prevent(self, *_args):
        return nullcontext()


class FakeDeviceManager:
    def __init__(self, devices, usb_device=None):
        self._impl = SimpleNamespace(close=lambda: None)
        self._devices = devices
        self._usb_device = usb_device

    def enumerate_devices(self):
        return self._devices

    def get_usb_device(self, timeout=0):
        if self._usb_device is None:
            raise Exception("no usb device")
        return self._usb_device


def fake_scan_module(devices):
    return SimpleNamespace(
        core=SimpleNamespace(DeviceManager=lambda impl: impl),
        _frida=SimpleNamespace(DeviceManager=lambda: FakeDeviceManager(devices)),
    )


class ConnectDeviceLoadingTests(IsolatedAppTestCase):
    async def test_connect_mount_schedules_scan_without_frida_on_ui_thread(self):
        scheduled_generations = []

        def enumerate_devices():
            raise AssertionError("frida enumeration must not run on the UI thread")

        def record_worker(app, generation):
            scheduled_generations.append(generation)

        fake_frida = SimpleNamespace(enumerate_devices=enumerate_devices)

        with tempfile.TemporaryDirectory() as tmp:
            previous_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                with patch.dict(sys.modules, {"frida": fake_frida}), patch.object(
                    NoxenApp,
                    "_populate_home_devices_worker",
                    record_worker,
                ):
                    app = NoxenApp(project_args(os.path.join(tmp, "missing.noxen")))
                    async with app.run_test(size=(100, 32)):
                        self.assertEqual(app.query_one("#main_tabs").active, "tab_home")
                        self.assertEqual(scheduled_generations, [1])
            finally:
                os.chdir(previous_cwd)

    def test_device_scan_worker_updates_connect_options_from_frida(self):
        fake_device = SimpleNamespace(name="Pixel", type="usb", id="device-1")
        local_device = SimpleNamespace(name="Local", type="local", id="local")
        fake_frida = fake_scan_module([local_device, fake_device])
        label = FakeLabel()
        select = FakeSelect()

        def query_one(selector, *_args):
            return select if selector == "#home_device" else label

        fake_app = SimpleNamespace(
            _connect_scan_generation=1,
            _home_devices=[],
            query_one=query_one,
            call_from_thread=lambda callback: callback(),
        )

        with patch.dict(sys.modules, {"frida": fake_frida}):
            NoxenApp._populate_home_devices_worker.__wrapped__(fake_app, 1)

        self.assertEqual(fake_app._home_devices, [fake_device])
        self.assertEqual(select.options, [("Pixel  (usb)", "device-1")])
        self.assertEqual(select.value, "device-1")
        self.assertEqual(label.text, "")

    def test_device_scan_preserves_existing_device_when_still_available(self):
        selected_device = SimpleNamespace(name="Selected", type="usb", id="selected")
        other_device = SimpleNamespace(name="Other", type="remote", id="other")
        fake_frida = fake_scan_module([selected_device, other_device])
        label = FakeLabel()
        select = FakeSelect()
        select.value = "selected"

        def query_one(selector, *_args):
            return select if selector == "#home_device" else label

        fake_app = SimpleNamespace(
            _connect_scan_generation=1,
            _home_devices=[],
            query_one=query_one,
            call_from_thread=lambda callback: callback(),
        )

        with patch.dict(sys.modules, {"frida": fake_frida}):
            NoxenApp._populate_home_devices_worker.__wrapped__(fake_app, 1)

        self.assertEqual(select.value, "selected")
        self.assertEqual(fake_app._home_devices, [selected_device, other_device])

    def test_device_scan_replaces_stale_selection(self):
        fake_device = SimpleNamespace(name="Pixel", type="usb", id="device-1")
        fake_frida = fake_scan_module([fake_device])
        label = FakeLabel()
        select = FakeSelect()
        select.value = "missing-device"

        def query_one(selector, *_args):
            return select if selector == "#home_device" else label

        fake_app = SimpleNamespace(
            _connect_scan_generation=1,
            _home_devices=[],
            query_one=query_one,
            call_from_thread=lambda callback: callback(),
        )

        with patch.dict(sys.modules, {"frida": fake_frida}):
            NoxenApp._populate_home_devices_worker.__wrapped__(fake_app, 1)

        self.assertEqual(select.value, "device-1")
        self.assertEqual(fake_app._home_devices, [fake_device])

    def test_device_scan_clears_selection_when_no_devices_exist(self):
        fake_frida = fake_scan_module([])
        label = FakeLabel()
        select = FakeSelect()
        select.value = "missing-device"

        def query_one(selector, *_args):
            return select if selector == "#home_device" else label

        fake_app = SimpleNamespace(
            _connect_scan_generation=1,
            _home_devices=[],
            query_one=query_one,
            call_from_thread=lambda callback: callback(),
        )

        with patch.dict(sys.modules, {"frida": fake_frida}):
            NoxenApp._populate_home_devices_worker.__wrapped__(fake_app, 1)

        self.assertEqual(select.value, SELECT_EMPTY)
        self.assertEqual(fake_app._home_devices, [])

    def test_device_scan_waits_for_usb_device_when_initial_list_is_stale(self):
        socket_device = SimpleNamespace(name="Local Socket", type="remote", id="socket")
        usb_device = SimpleNamespace(name="Android Emulator", type="usb", id="emulator-5554")
        fake_frida = SimpleNamespace(
            get_device_manager=lambda: FakeDeviceManager([socket_device], usb_device=usb_device),
        )

        devices = enumerate_preferred_devices(fake_frida, usb_timeout=1)

        self.assertEqual(devices, [socket_device, usb_device])

    def test_stale_scan_cannot_replace_current_connection_context(self):
        selected = FakeSelect()
        label = FakeLabel()
        current = [SimpleNamespace(id="new", name="New", type="usb")]
        app = SimpleNamespace(
            _connect_scan_generation=2, _home_devices=current,
            query_one=lambda selector, *_: selected if selector == "#home_device" else label,
            call_from_thread=lambda callback: callback(),
        )
        with patch.dict(sys.modules, {"frida": fake_scan_module([])}):
            NoxenApp._populate_home_devices_worker.__wrapped__(app, 1)
        self.assertIs(app._home_devices, current)
        self.assertEqual(selected.options, [])

    def test_app_listing_uses_the_scan_context_not_global_lookup(self):
        calls = []
        selected = FakeSelect()
        device = SimpleNamespace(enumerate_applications=lambda: [
            SimpleNamespace(identifier="dev.noxen.playground"),
        ])
        def resolve(device_id):
            calls.append(device_id)
            return device
        scan = SimpleNamespace(get_device=resolve)
        app = SimpleNamespace(
            _home_devices=scan,
            query_one=lambda *_: selected,
            call_from_thread=lambda callback: callback(),
        )
        app._target_scan_is_current = lambda *_args: True
        with patch.dict(sys.modules, {"frida": SimpleNamespace()}):
            NoxenApp._populate_target_apps_worker.__wrapped__(app, "emulator-5554", "f", scan, 1)
        self.assertEqual(calls, ["emulator-5554"])
        self.assertEqual(selected.options, [("dev.noxen.playground", "dev.noxen.playground")])

    def test_old_app_list_and_error_are_ignored_after_a_device_refresh(self):
        for fail in (False, True):
            with self.subTest(fail=fail):
                def list_apps():
                    if fail:
                        raise RuntimeError("Old connection failed")
                    return [SimpleNamespace(identifier="old.app")]
                scan = SimpleNamespace(get_device=lambda _: SimpleNamespace(
                    enumerate_applications=list_apps,
                ))
                callbacks = []
                selected = FakeSelect()
                app = SimpleNamespace(
                    _home_devices=scan, query_one=lambda *_: selected,
                    call_from_thread=callbacks.append,
                )
                app._target_scan_is_current = lambda _gen, _id, _mode, devices: devices is app._home_devices
                with patch.dict(sys.modules, {"frida": SimpleNamespace()}):
                    NoxenApp._populate_target_apps_worker.__wrapped__(app, "old", "f", scan, 1)
                app._home_devices = []
                for callback in callbacks:
                    callback()
                self.assertEqual(selected.options, [])


if __name__ == "__main__":
    unittest.main()
