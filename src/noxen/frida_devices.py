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
