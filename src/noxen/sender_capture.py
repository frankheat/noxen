"""Convert complete, supported captures into editable Sender arguments."""

from noxen.sender import SenderError


def _complete(node, path):
    if not isinstance(node, dict):
        raise SenderError(f"{path}: no structured capture is available")
    if any(value for key, value in node.items() if key in (
            "error", "errors", "omitted", "descriptionError", "mimeTypesOmitted", "truncatedFields",
            "unreadableFields", "categoriesReadError") or key.endswith("Truncated") or key == "truncated"):
        raise SenderError(f"{path}: capture is incomplete; create or repair this value explicitly")
    # Older captures did not flag every truncated ClipData/category string.
    # Refuse ambiguous values at the capture boundary instead of replaying a prefix.
    def boundary(value):
        if isinstance(value, str):
            return len(value.encode("utf-16-le", errors="surrogatepass")) // 2 >= 2048
        if isinstance(value, list):
            return any(boundary(item) for item in value if not isinstance(item, dict))
        return False
    if any(boundary(value) for value in node.values()):
        raise SenderError(f"{path}: a value reaches the capture length limit; enter it explicitly")


def _bundle(node, path):
    if node is None:
        return {}
    _complete(node, path)
    items = node.get("items")
    if node.get("kind") != "bundle" or not isinstance(items, list) or node.get("count") != len(items):
        raise SenderError(f"{path}: Bundle is incomplete")
    result = {}
    for item in items:
        if item.get("keyTruncated") or item["key"] in result:
            raise SenderError(f"{path}: a key was truncated or duplicated")
        result[item["key"]] = _value(item["value"], f"{path}.{item['key']}")
    return result


def _value(node, path):
    _complete(node, path)
    kind = node.get("kind")
    if kind == "null":
        return {"type": "String", "value": None}
    if kind == "intent":
        return {"type": "Intent", "value": _intent(node, path, nested=True)}
    if kind == "bundle" and node.get("type") == "android.os.Bundle":
        return {"type": "Bundle", "value": _bundle(node, path)}
    java_type = node.get("type", "")
    if kind == "scalar" and (java_type == "android.net.Uri" or java_type.startswith("android.net.Uri$")):
        return {"type": "Uri", "value": node["value"]}
    types = {"java.lang.String": "String", "java.lang.Boolean": "boolean", "java.lang.Byte": "byte",
             "java.lang.Short": "short", "java.lang.Integer": "int", "java.lang.Long": "long",
             "java.lang.Float": "float", "java.lang.Double": "double", "java.lang.Character": "char"}
    if kind == "scalar" and node.get("type") in types:
        target = types[node["type"]]
        value = node["value"]
        if target == "boolean":
            if value not in ("true", "false"):
                raise SenderError(f"{path}: invalid captured boolean")
            value = value == "true"
        elif target in ("byte", "short", "int"):
            value = int(value)
        elif target in ("float", "double"):
            value = float(value)
        return {"type": target, "value": value}
    if kind == "array":
        target = {"[Ljava.lang.String;": "String", "[I": "int", "[J": "long", "[Z": "boolean",
                  "[B": "byte", "[S": "short", "[F": "float", "[D": "double", "[C": "char",
                  "[Landroid.content.Intent;": "Intent"}.get(node.get("type"))
        if target and node.get("count") == len(node.get("items", [])):
            items = [_value(item, f"{path}[{index}]") for index, item in enumerate(node["items"])]
            if all(item["type"] == target or item["value"] is None for item in items):
                return {"type": target + "[]", "value": [item["value"] for item in items]}
    raise SenderError(f"{path}: cannot reconstruct {node.get('type') or kind}; replace or remove it explicitly")


def _intent(info, path, nested=False):
    _complete(info, path)
    result = {}
    for key in ("component", "action", "data", "mimeType", "package", "flags", "categories", "selector", "clipData"):
        if key not in info:
            raise SenderError(f"{path}.{key}: field was not captured")
        if key == "selector":
            result[key] = None if info[key] is None else _intent(info[key], f"{path}.selector", nested=True)
        elif key == "clipData":
            clip = info[key]
            if clip is None:
                result[key] = None
                continue
            _complete(clip, f"{path}.clipData")
            if clip.get("kind") != "clipdata" or clip.get("count") != len(clip.get("items", [])):
                raise SenderError(f"{path}.clipData: incomplete capture")
            items = []
            for item in clip["items"]:
                _complete(item, f"{path}.clipData.item")
                if not all(k in item for k in ("text", "html", "uri", "intent")):
                    raise SenderError(f"{path}.clipData: item fields were not captured")
                items.append({"text": item["text"], "htmlText": item["html"], "uri": item["uri"],
                              "intent": None if item["intent"] is None else _intent(item["intent"], path + ".clipData.intent", nested=True)})
            result[key] = {"label": clip.get("label"), "mimeTypes": clip.get("mimeTypes"), "items": items}
        else:
            result[key] = info[key]
    result["flags"] = int(result["flags"]) & 0xffffffff
    if nested:
        if "extras" not in info:
            raise SenderError(f"{path}.extras: not captured")
        result["extras"] = None if info["extras"] is None else _bundle(info["extras"], path + ".extras")
    else:
        metadata = info.get("extrasMeta")
        if (metadata is None and info.get("extras")) or (metadata and (metadata.get("error") or metadata.get("omitted"))):
            raise SenderError(f"{path}.extras: completeness cannot be established")
        result["extras"] = {}
        for key, item in info.get("extras", {}).items():
            if item.get("keyTruncated") or item.get("structuredVersion") != 1:
                raise SenderError(f"{path}.extras.{key}: incomplete or legacy capture")
            result["extras"][key] = _value(item.get("structured"), path + ".extras.'" + key + "'")
        if not result["extras"] and metadata is None:
            result["extras"] = None
    return result


def prepare_intent_request(entry, operation):
    """Operation is always explicit, especially for receiving hooks."""
    from noxen.sender import INTENT_OPERATIONS
    if operation not in INTENT_OPERATIONS:
        raise SenderError("Choose an Intent sending operation")
    request = {"operation": operation, "intent": _intent(entry.get("intent"), "intent")}
    if operation in ("sendBroadcast", "sendOrderedBroadcast"):
        surface = entry.get("attack_surface") or {}
        if "broadcastPermission" in surface:
            permission = surface["broadcastPermission"]
            if permission is None:
                request["receiverPermission"] = None
            elif isinstance(permission, dict) and isinstance(permission.get("name"), str):
                request["receiverPermission"] = permission["name"]
            else:
                raise SenderError("The captured receiver permission must be entered explicitly")
    # Do not add NEW_TASK or change any captured field. The editor can repair a
    # request that is unsuitable for an Application-context Activity launch.
    return request


def prepare_component_request(package, component):
    kind = component.get("type")
    if kind == "provider":
        authorities = [value for value in (component.get("authority") or "").split(";") if value]
        if len(authorities) != 1:
            raise SenderError("Choose a provider authority explicitly in a new request")
        return {"operation": "query", "uri": "content://" + authorities[0]}
    operation = {"activity": "startActivity", "receiver": "sendBroadcast", "service": "startService"}.get(kind)
    if operation is None or not package or not component.get("name"):
        raise SenderError("This component cannot be prepared as a Sender request")
    return {"operation": operation, "intent": {"component": package + "/" + component["name"],
            "flags": 0x10000000 if operation == "startActivity" else 0}}


# Hooked methods whose captured Intent maps to one sending operation. Receiving
# hooks map to the call that would deliver such an Intent.
CAPTURE_OPERATIONS = {
    "startActivity": "startActivity", "startActivityForResult": "startActivity",
    "getIntent": "startActivity", "onNewIntent": "startActivity", "onCreate": "startActivity",
    "getActivity": "startActivity",
    "sendBroadcast": "sendBroadcast", "onReceive": "sendBroadcast", "getBroadcast": "sendBroadcast",
    "sendOrderedBroadcast": "sendOrderedBroadcast",
    "startService": "startService", "onStartCommand": "startService", "onHandleIntent": "startService",
    "getService": "startService",
    "startForegroundService": "startForegroundService",
}


def capture_operation(entry):
    """The sending operation implied by the hook that captured `entry`, or None when it is a choice."""
    return CAPTURE_OPERATIONS.get((entry or {}).get("method"))


_RESOLVER = "android.content.ContentResolver"
_TRANSPORT = "android.content.ContentProvider$Transport"
_URI = "android.net.Uri"
_STRING = "java.lang.String"
_STRINGS = "[Ljava.lang.String;"
_BUNDLE = "android.os.Bundle"
_VALUES = "android.content.ContentValues"
_READS = ("openFile", "openAssetFile", "openTypedAssetFile", "openFileDescriptor", "openInputStream",
          "openTypedAssetFileDescriptor")


def prepare_monitor_request(event):
    """Rebuild a provider call recorded by Monitor. Anything not captured in full is refused."""
    clazz, method = event.get("class"), event.get("method")
    types, values = list(event.get("types") or []), event.get("arguments")
    if clazz not in (_RESOLVER, _TRANSPORT):
        raise SenderError("Only content provider calls can be sent to Sender from Monitor")
    if not isinstance(values, list) or len(values) != len(types):
        raise SenderError("This event was recorded without its arguments")
    if clazz == _TRANSPORT and types[:1] == ["android.content.AttributionSource"]:
        types, values = types[1:], values[1:]

    def text(value, what, nullable=True):
        if not isinstance(value, dict) or value.get("opaque") or value.get("captureError") or value.get("truncated") \
                or "value" not in value or not (isinstance(value["value"], str) or (nullable and value["value"] is None)):
            raise SenderError(f"{what} was not captured completely; create this request in Sender")
        return value["value"]

    def strings(value, what):
        if isinstance(value, dict) and "items" not in value and value.get("value", 0) is None:
            return None
        items = value.get("items") if isinstance(value, dict) else None
        if not isinstance(items, list) or value.get("count") != len(items):
            raise SenderError(f"{what} was not captured completely; create this request in Sender")
        return [text(item, what) for item in items]

    def absent(value, what):
        if not isinstance(value, dict) or value.get("opaque") or value.get("value", 0) is not None:
            raise SenderError(f"{what} is not captured by Monitor; create this request in Sender")

    def selection(request, start):
        """Either (selection, selectionArgs[, sortOrder]) or one query-arguments Bundle."""
        if types[start:start + 1] == [_BUNDLE]:
            bundle = values[start]
            query = bundle.get("queryArguments") if isinstance(bundle, dict) else None
            if isinstance(query, dict):
                request["selection"] = text(query.get("selection"), "Selection")
                request["selectionArgs"] = strings(query.get("selectionArgs"), "Selection arguments")
                return query
            absent(bundle, "This Bundle")
            return {}
        request["selection"] = text(values[start], "Selection")
        request["selectionArgs"] = strings(values[start + 1], "Selection arguments")
        return None

    if method == "call":
        first = text(values[0], "Authority", nullable=False)
        request = {"operation": "call", "uri": first if types[0] == _URI else "content://" + first,
                   "method": text(values[1], "Method", nullable=False), "arg": text(values[2], "Argument")}
        absent(values[3], "Bundle extras")
        return request
    if not types or types[0] != _URI:
        raise SenderError("This provider call has no content URI")
    uri = text(values[0], "URI", nullable=False)
    if method == "query":
        request = {"operation": "query", "uri": uri, "projection": strings(values[1], "Projection")}
        query = selection(request, 2)
        if query is None:
            request["sortOrder"] = text(values[4], "Sort order")
        elif query:
            request["sortOrder"] = text(query.get("sortOrder"), "Sort order")
        return request
    if method == "delete":
        request = {"operation": "delete", "uri": uri}
        selection(request, 1)
        return request
    if method in ("insert", "update") and _VALUES in types:
        raise SenderError("ContentValues are not captured by Monitor; create this request in Sender")
    if method in _READS:
        return {"operation": "openFileDescriptor", "uri": uri}
    raise SenderError(f"{method} cannot be sent from Sender")
