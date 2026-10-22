import threading
import weakref


def _close_manager(impl):
    try:
        impl.close()
    except Exception:
        pass


def _close_manager_async(impl):
    # Replacing a scan can release its last reference on Textual's UI thread.
    threading.Thread(target=_close_manager, args=(impl,), daemon=True).start()


class DeviceScan(list):
    """Discovered devices and their independent Frida discovery context.

    A bound get_device method keeps this context alive for a connection, even
    when Home replaces its scan. Unused contexts close outside the UI thread.
    """

    def __init__(self, manager, devices):
        super().__init__(devices)
        self._manager = manager
        finalizer = weakref.finalize(self, _close_manager_async, manager._impl)
        finalizer.atexit = False

    def get_device(self, device_id, timeout=0):
        return self._manager.get_device(device_id, timeout=timeout)


def scan_devices(frida_module, usb_timeout: int = 1):
    # Use the same constructor as frida.get_device_manager(), but not its
    # singleton: an Android backend started without ADB may never reconnect.
    manager = frida_module.core.DeviceManager(frida_module._frida.DeviceManager())
    try:
        return DeviceScan(manager, enumerate_preferred_devices(manager, usb_timeout))
    except Exception:
        _close_manager(manager._impl)
        raise


def enumerate_preferred_devices(frida_module, usb_timeout: int = 1):
    manager = getattr(frida_module, "get_device_manager", lambda: None)()
    if manager is not None:
        devices = list(manager.enumerate_devices())
    else:
        devices = list(frida_module.enumerate_devices())

    if not any(getattr(device, "type", None) == "usb" for device in devices):
        get_usb_device = getattr(manager, "get_usb_device", None) if manager is not None else None
        if get_usb_device is None:
            get_usb_device = getattr(frida_module, "get_usb_device", None)
        if get_usb_device is not None:
            try:
                usb_device = get_usb_device(timeout=usb_timeout)
            except Exception:
                usb_device = None
            if usb_device is not None and all(device.id != usb_device.id for device in devices):
                devices.append(usb_device)

    return prefer_non_local_devices(devices)


def prefer_non_local_devices(devices):
    device_list = list(devices)
    non_local = [device for device in device_list if getattr(device, "type", None) != "local"]
    return non_local if non_local else device_list
