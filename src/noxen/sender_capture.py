"""Convert complete, supported captures into editable Sender arguments."""

from functools import wraps

from noxen.sender import SenderError, intent_flags_for_json


def refuses_malformed(function):
    """Captures come from the device and from saved projects: a wrong shape is refused like a missing field."""
    @wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except SenderError:
            raise
        except (AttributeError, IndexError, KeyError, TypeError, ValueError):
            raise SenderError("This capture is malformed; create the request in Sender") from None
    return guarded


INCOMPLETE = ("error", "errors", "omitted", "descriptionError", "mimeTypesOmitted", "truncatedFields",
              "unreadableFields", "categoriesReadError")
SKIP = object()  # A value that could not be rebuilt at all and is left out.


def _fail(notes, message):
    """Strict conversion refuses; the JSON view keeps going and lists what is missing."""
    if notes is None:
        raise SenderError(message)
    if message not in notes:
        notes.append(message)


def _at_limit(value):
    """Older captures did not flag every truncated string: one at the capture limit may be a prefix."""
    if isinstance(value, str):
        return len(value.encode("utf-16-le", errors="surrogatepass")) // 2 >= 2048
    if isinstance(value, list):
        return any(_at_limit(item) for item in value if not isinstance(item, dict))
    return False


def _complete(node, path, notes=None):
    """True when `node` was captured in full. Otherwise the gap is refused, or noted when `notes` is given."""
    if not isinstance(node, dict):
        _fail(notes, f"{path}: no structured capture is available")
        return False
    if any(value for key, value in node.items()
           if key in INCOMPLETE or key.endswith("Truncated") or key == "truncated"):
        _fail(notes, f"{path}: capture is incomplete; create or repair this value explicitly")
        return False
    if any(_at_limit(value) for value in node.values()):
        _fail(notes, f"{path}: a value reaches the capture length limit; enter it explicitly")
        return False
    return True


def _bundle(node, path, notes=None, *, preserve_clip_positions=False):
    if node is None:
        return {}
    if not isinstance(node, dict):
        _fail(notes, f"{path}: no structured capture is available")
        return {}
    _complete(node, path, notes)  # Without `notes` an incomplete Bundle is refused here.
    items = node.get("items")
    if node.get("kind") != "bundle" or not isinstance(items, list) or node.get("count") != len(items):
        _fail(notes, f"{path}: Bundle is incomplete")
        items = items if isinstance(items, list) else []
    result = {}
    for item in items:
        if item.get("keyTruncated") or item["key"] in result:
            _fail(notes, f"{path}: a key was truncated or duplicated")
            continue
        value = _value(item["value"], f"{path}.{item['key']}", notes,
                       preserve_clip_positions=preserve_clip_positions)
        if value is not SKIP:
            result[item["key"]] = value
    return result


def _value(node, path, notes=None, *, preserve_clip_positions=False):
    """One typed value, or SKIP when it was not captured in full (only possible with `notes`)."""
    if not _complete(node, path, notes):
        return SKIP
    kind = node.get("kind")
    if kind == "null":
        return {"type": "String", "value": None}
    if kind == "intent":
        return {"type": "Intent", "value": _intent(node, path, nested=True, notes=notes,
                                                   preserve_clip_positions=preserve_clip_positions)}
    if kind == "bundle" and node.get("type") == "android.os.Bundle":
        return {"type": "Bundle", "value": _bundle(node, path, notes,
                                                   preserve_clip_positions=preserve_clip_positions)}
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
                _fail(notes, f"{path}: invalid captured boolean")
                return SKIP
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
            items = [_value(item, f"{path}[{index}]", notes, preserve_clip_positions=preserve_clip_positions)
                     for index, item in enumerate(node["items"])]
            if all(item is not SKIP and (item["type"] == target or item["value"] is None) for item in items):
                return {"type": target + "[]", "value": [item["value"] for item in items]}
    _fail(notes, f"{path}: cannot reconstruct {node.get('type') or kind}; replace or remove it explicitly")
    return SKIP


def _intent(info, path, nested=False, notes=None, *, preserve_clip_positions=False, operation=None):
    if not isinstance(info, dict):
        _fail(notes, f"{path}: no structured capture is available")
        return {}
    # A partial Intent keeps what was captured and leaves out the fields the agent reported as cut or unread.
    dropped = set()
    gaps = None if notes is None else []
    if not _complete(info, path, gaps):  # Strict conversion has already refused here.
        dropped = {*(info.get("truncatedFields") or ()), *(info.get("unreadableFields") or ())}
        if info.get("categoriesReadError"):
            dropped.add("categories")
        # Name the fields that are left out, rather than only saying the Intent is incomplete.
        _fail(notes, f"{path}: {', '.join(sorted(dropped))} not captured in full" if dropped else gaps[0])
    result = {}
    for key in ("component", "action", "data", "mimeType", "package", "flags", "categories", "selector", "clipData"):
        if key not in info:
            _fail(notes, f"{path}.{key}: field was not captured")
            continue
        if key in dropped or (key not in ("selector", "clipData") and _at_limit(info[key])):
            continue
        if key == "selector":
            result[key] = None if info[key] is None else _intent(
                info[key], f"{path}.selector", nested=True, notes=notes,
                preserve_clip_positions=preserve_clip_positions)
        elif key == "clipData":
            clip = info[key]
            if clip is None:
                result[key] = None
                continue
            if not isinstance(clip, dict):
                _fail(notes, f"{path}.clipData: no structured capture is available")
                continue
            _complete(clip, f"{path}.clipData", notes)
            if clip.get("kind") != "clipdata" or clip.get("count") != len(clip.get("items", [])):
                _fail(notes, f"{path}.clipData: incomplete capture")
            items = []
            captured_items = clip.get("items", [])
            for item in captured_items:
                if not _complete(item, f"{path}.clipData.item", notes):
                    continue
                if not all(k in item for k in ("text", "html", "uri", "intent")):
                    _fail(notes, f"{path}.clipData: item fields were not captured")
                items.append({"text": item.get("text"), "htmlText": item.get("html"), "uri": item.get("uri"),
                              "intent": None if item.get("intent") is None else
                              _intent(item["intent"], path + ".clipData.intent", nested=True, notes=notes,
                                      preserve_clip_positions=preserve_clip_positions)})
            if preserve_clip_positions and len(items) != len(captured_items):
                # Intercept paths address the original ClipData by index. A
                # compacted list is safe to display elsewhere, but not to edit.
                _fail(notes, f"{path}.clipData: omitted from the editor to preserve item positions")
                continue
            mime_types = [value for value in clip.get("mimeTypes") or [] if not _at_limit(value)]
            if items and mime_types:
                result[key] = {"label": None if _at_limit(clip.get("label")) else clip.get("label"),
                               "mimeTypes": mime_types, "items": items}
            else:
                _fail(notes, f"{path}.clipData: nothing usable was captured")
        else:
            result[key] = info[key]
    if "flags" in result:
        result["flags"] = intent_flags_for_json(int(result["flags"]) & 0xffffffff, operation)
    if nested:
        if "extras" not in info:
            _fail(notes, f"{path}.extras: not captured")
        result["extras"] = None if info.get("extras") is None else _bundle(
            info["extras"], path + ".extras", notes, preserve_clip_positions=preserve_clip_positions)
    else:
        metadata = info.get("extrasMeta")
        if (metadata is None and info.get("extras")) or (metadata and (metadata.get("error") or metadata.get("omitted"))):
            _fail(notes, f"{path}.extras: completeness cannot be established")
        result["extras"] = {}
        for key, item in (info.get("extras") or {}).items():
            if item.get("keyTruncated") or item.get("structuredVersion") != 1:
                _fail(notes, f"{path}.extras.{key}: incomplete or legacy capture")
                continue
            value = _value(item.get("structured"), path + ".extras.'" + key + "'", notes,
                           preserve_clip_positions=preserve_clip_positions)
            if value is not SKIP:
                result["extras"][key] = value
        if not result["extras"] and metadata is None:
            result["extras"] = None
    return result


def _receiver_permission(entry, request, notes=None):
    surface = entry.get("attackSurface") or entry.get("attack_surface") or {}
    if "broadcastPermission" in surface:
        permission = surface["broadcastPermission"]
        if permission is None:
            request["receiverPermission"] = None
        elif isinstance(permission, dict) and isinstance(permission.get("name"), str):
            request["receiverPermission"] = permission["name"]
        else:
            _fail(notes, "The captured receiver permission must be entered explicitly")


@refuses_malformed
def prepare_intent_request(entry, operation, notes=None):
    """Operation is always explicit, especially for receiving hooks.

    A capture with gaps is refused. With a `notes` list it is rebuilt without
    them instead, and each value left out is described in `notes`.
    """
    from noxen.sender import INTENT_OPERATIONS
    if operation not in INTENT_OPERATIONS:
        raise SenderError("Choose an Intent sending operation")
    request = {"operation": operation, "intent": _intent(entry.get("intent"), "intent", notes=notes,
                                                        operation=operation)}
    if operation in ("sendBroadcast", "sendOrderedBroadcast"):
        _receiver_permission(entry, request, notes)
    # Do not add NEW_TASK or change any captured field. The editor can repair a
    # request that is unsuitable for an Application-context Activity launch.
    return request


@refuses_malformed
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
            "flags": ["FLAG_ACTIVITY_NEW_TASK"] if operation == "startActivity" else []}}


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


def capture_as_request(entry):
    """The captured Intent in Sender's request format, for reading.

    `hook` names the hooked call and is for reading only: To Sender converts
    the capture itself with prepare_intent_request, never this view. Nothing is
    refused: what could not be rebuilt is left out and listed under
    `notCaptured`. The operation is shown only when the hook was that call: for
    a receiving hook such as getIntent, how the Intent was sent is not known.
    """
    from noxen.sender import INTENT_OPERATIONS
    notes = []
    request = {}
    try:
        method = entry.get("method") if isinstance(entry, dict) else None
        operation = method if method in INTENT_OPERATIONS else None
        if operation is not None:
            request["operation"] = operation
        request["intent"] = _intent(entry.get("intent") if isinstance(entry, dict) else None, "intent", notes=notes,
                                    operation=capture_operation(entry) or operation)
        if operation in ("sendBroadcast", "sendOrderedBroadcast"):
            _receiver_permission(entry, request, notes)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        notes.append("This capture is malformed and could not be read in full")
    if notes:
        request = {"notCaptured": notes, **request}
    hook = capture_hook_label(entry)
    if hook:
        request = {"hook": hook, **request}
    return request


def capture_hook_label(entry):
    """`Class.method()` of the hook that captured `entry`, for reading only."""
    if not isinstance(entry, dict):
        return None
    clazz, method = entry.get("class"), entry.get("method")
    clazz = clazz if isinstance(clazz, str) and clazz else None
    method = method if isinstance(method, str) and method else None
    if method is None:
        return clazz
    return f"{clazz}.{method}()" if clazz else f"{method}()"


def capture_operation(entry):
    """The sending operation implied by the hook that captured `entry`, or None when it is a choice."""
    method = entry.get("method") if isinstance(entry, dict) else None
    return CAPTURE_OPERATIONS.get(method) if isinstance(method, str) else None


_RESOLVER = "android.content.ContentResolver"
_TRANSPORT = "android.content.ContentProvider$Transport"
_URI = "android.net.Uri"
_STRING = "java.lang.String"
_STRINGS = "[Ljava.lang.String;"
_BUNDLE = "android.os.Bundle"
_VALUES = "android.content.ContentValues"
_READS = ("openFile", "openAssetFile", "openTypedAssetFile", "openFileDescriptor", "openInputStream",
          "openTypedAssetFileDescriptor")


@refuses_malformed
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
