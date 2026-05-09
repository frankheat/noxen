import unittest
from types import SimpleNamespace

from noxen.frida_devices import prefer_non_local_devices


class FridaDeviceTests(unittest.TestCase):
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
