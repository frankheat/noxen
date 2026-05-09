def prefer_non_local_devices(devices):
    device_list = list(devices)
    non_local = [device for device in device_list if getattr(device, "type", None) != "local"]
    return non_local if non_local else device_list
