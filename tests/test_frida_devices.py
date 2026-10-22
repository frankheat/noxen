import gc
import threading
import unittest
import weakref
from types import SimpleNamespace

from noxen.frida_devices import prefer_non_local_devices, scan_devices
from noxen.filters import FilterManager
from noxen.frida_session import FridaSession, SessionConfig


class Manager:
    def __init__(self, devices):
        self.devices = devices
        self.closed = threading.Event()
        self.close_thread = None
        self._impl = self

    def close(self):
        self.close_thread = threading.get_ident()
        self.closed.set()

    def enumerate_devices(self):
        return list(self.devices)

    def get_usb_device(self, timeout=0):
        raise RuntimeError("USB unavailable")

    def get_device(self, device_id, timeout=0):
        return next(device for device in self.devices if device.id == device_id)


def module_for(managers):
    pending = iter(managers)
    return SimpleNamespace(
        core=SimpleNamespace(DeviceManager=lambda impl: impl),
        _frida=SimpleNamespace(DeviceManager=lambda: next(pending)),
    )


class FridaDeviceTests(unittest.TestCase):
    def test_refresh_replaces_failed_backend_without_using_global_manager(self):
        socket = SimpleNamespace(id="socket", type="remote")
        usb = SimpleNamespace(id="emulator-5554", type="usb")
        old, recovered = Manager([socket]), Manager([socket, usb])
        module = module_for([old, recovered])
        first = scan_devices(module)
        second = scan_devices(module)
        self.assertEqual(first, [socket])
        self.assertEqual(second, [socket, usb])
        self.assertIs(second.get_device(usb.id, timeout=5), usb)
        self.assertFalse(old.closed.is_set())
        self.assertFalse(recovered.closed.is_set())

    def test_connection_resolver_pins_old_scan_during_refresh(self):
        usb = SimpleNamespace(id="emulator-5554", type="usb")
        old, new = Manager([usb]), Manager([usb])
        module = module_for([old, new])
        scan = scan_devices(module)
        reference = weakref.ref(scan)
        resolver = scan.get_device
        scan = scan_devices(module)
        gc.collect()
        self.assertIsNotNone(reference())
        self.assertFalse(old.closed.is_set())
        self.assertIs(resolver(usb.id), usb)
        del resolver
        gc.collect()
        self.assertIsNone(reference())
        self.assertTrue(old.closed.wait(2))
        self.assertNotEqual(old.close_thread, threading.get_ident())
        self.assertFalse(new.closed.is_set())

    def test_scan_error_closes_only_the_failed_manager(self):
        good, bad = Manager([]), Manager([])
        def fail():
            raise RuntimeError("enumeration failed")
        bad.enumerate_devices = fail
        module = module_for([good, bad])
        scan = scan_devices(module)
        with self.assertRaisesRegex(RuntimeError, "enumeration failed"):
            scan_devices(module)
        self.assertTrue(bad.closed.is_set())
        self.assertFalse(good.closed.is_set())

    def test_context_survives_a_cleanup_that_outlives_its_session_owner(self):
        manager = Manager([])
        scan = scan_devices(module_for([manager]))
        owner = FridaSession(
            SessionConfig(), FilterManager(), lambda _: None,
            lambda _: None, lambda: (False, 0), device_resolver=scan.get_device,
        )
        entered, release, done = threading.Event(), threading.Event(), threading.Event()
        def detach():
            entered.set()
            release.wait(3)
            done.set()
        owner._session = SimpleNamespace(detach=detach)
        try:
            owner.cleanup()
            self.assertTrue(entered.is_set())
            del owner, scan
            gc.collect()
            self.assertFalse(manager.closed.is_set())
        finally:
            release.set()
        self.assertTrue(done.wait(2))
        gc.collect()
        self.assertTrue(manager.closed.wait(2))

    def test_prefer_non_local_devices_returns_non_local_when_available(self):
        local = SimpleNamespace(type="local")
        usb = SimpleNamespace(type="usb")
        remote = SimpleNamespace(type="remote")

        self.assertEqual(prefer_non_local_devices([local, usb, remote]), [usb, remote])

    def test_prefer_non_local_devices_keeps_local_when_it_is_the_only_choice(self):
        local = SimpleNamespace(type="local")

        self.assertEqual(prefer_non_local_devices([local]), [local])


if __name__ == "__main__":
    unittest.main()
