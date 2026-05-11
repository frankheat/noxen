import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from noxen.app import NoxenApp
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


class ConnectDeviceLoadingTests(unittest.IsolatedAsyncioTestCase):
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
        fake_frida = SimpleNamespace(enumerate_devices=lambda: [local_device, fake_device])
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
        fake_frida = SimpleNamespace(enumerate_devices=lambda: [selected_device, other_device])
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
        fake_frida = SimpleNamespace(enumerate_devices=lambda: [fake_device])
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
        fake_frida = SimpleNamespace(enumerate_devices=lambda: [])
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


if __name__ == "__main__":
    unittest.main()
