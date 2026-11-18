"""Sender request format. Validation never repairs or silently drops a field."""

import copy
import json
import math

from noxen.intent_mods import normalize_component
from noxen.rendering import INTENT_FLAGS

INTENT_OPERATIONS = (
    "startActivity", "sendBroadcast", "sendOrderedBroadcast", "startService", "startForegroundService", "stopService",
)
PROVIDER_OPERATIONS = ("query", "getType", "insert", "update", "delete", "call", "openFileDescriptor")
OPERATIONS = INTENT_OPERATIONS + PROVIDER_OPERATIONS
MAX_REQUEST_BYTES = 256 * 1024
NAMED_INTENT_FLAGS = {name: bit for bit, names in INTENT_FLAGS for name in names}


def intent_flag_family(operation):
    if operation == "startActivity":
        return "FLAG_ACTIVITY_"
    if operation in ("sendBroadcast", "sendOrderedBroadcast"):
        return "FLAG_RECEIVER_"
    return None


def intent_flags_for_json(mask, operation=None):
    """Name a captured mask only when every bit has an unambiguous name."""
    family = intent_flag_family(operation)
    remaining = mask
    names = []
    for bit, aliases in INTENT_FLAGS:
        if not mask & bit:
            continue
        choices = aliases if len(aliases) == 1 else [name for name in aliases if family and name.startswith(family)]
        if len(choices) != 1:
            return mask
        names.append(choices[0])
        remaining &= ~bit
    return mask if remaining else names


class SenderError(ValueError):
    pass


def fields(value, allowed, path):
    if not isinstance(value, dict):
        raise SenderError(f"{path}: expected an object")
    unknown = set(value) - set(allowed)
    if unknown:
        raise SenderError(f"{path}: unsupported fields: {', '.join(sorted(unknown))}")


def string(value, path, nullable=False):
    if nullable and value is None:
        return
    if not isinstance(value, str):
        raise SenderError(f"{path}: expected text")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise SenderError(f"{path}: unpaired UTF-16 surrogate is not supported") from None


def intent_flag_mask(value, path, *, allow_names=False):
    if type(value) is int and 0 <= value <= 0xFFFFFFFF:
        return value
    if allow_names and isinstance(value, list):
        mask = 0
        for index, name in enumerate(value):
            if not isinstance(name, str) or name not in NAMED_INTENT_FLAGS:
                raise SenderError(f"{path}[{index}]: unknown Intent flag {name!r}")
            mask |= NAMED_INTENT_FLAGS[name]
        return mask
    expected = "unsigned 32-bit integer or list of Intent flag names" if allow_names else "unsigned 32-bit integer"
    raise SenderError(f"{path}: expected {expected}")


def typed_values(values, path, depth=0, *, flag_mode=None):
    if depth > 8:
        raise SenderError(f"{path}: nesting exceeds 8 levels")
    if not isinstance(values, dict):
        raise SenderError(f"{path}: expected keyed typed values")
    for key, item in values.items():
        string(key, path)
        fields(item, ("type", "value"), f"{path}.{key}")
        kind, value = item.get("type"), item.get("value")
        if "value" not in item:
            raise SenderError(f"{path}.{key}: value is required, including for null")
        if kind == "String":
            string(value, f"{path}.{key}", nullable=True)
        elif kind == "boolean":
            if type(value) is not bool:
                raise SenderError(f"{path}.{key}: expected boolean")
        elif kind in ("byte", "short", "int", "long"):
            # Longs travel as decimal strings to avoid JavaScript precision loss.
            if kind == "long":
                if not isinstance(value, str) or not value or value.strip() != value:
                    raise SenderError(f"{path}.{key}: long requires a decimal string")
                try:
                    number = int(value, 10)
                except ValueError:
                    raise SenderError(f"{path}.{key}: invalid long") from None
                if str(number) != value:
                    raise SenderError(f"{path}.{key}: use canonical decimal notation")
            else:
                if type(value) is not int:
                    raise SenderError(f"{path}.{key}: expected integer")
                number = value
            bits = {"byte": 8, "short": 16, "int": 32, "long": 64}[kind]
            if not -(1 << (bits - 1)) <= number < (1 << (bits - 1)):
                raise SenderError(f"{path}.{key}: {kind} out of range")
        elif kind in ("double", "float"):
            try:
                finite = type(value) in (int, float) and math.isfinite(value)
            except OverflowError:
                finite = False
            if not finite:
                raise SenderError(f"{path}.{key}: expected finite number")
            if kind == "float" and abs(value) > 3.4028234663852886e38:
                raise SenderError(f"{path}.{key}: float out of range")
        elif kind == "char":
            string(value, f"{path}.{key}")
            if not isinstance(value, str) or len(value) != 1 or ord(value) > 0xffff:
                raise SenderError(f"{path}.{key}: expected one UTF-16 character")
        elif kind == "Bundle":
            if value is not None:
                typed_values(value, f"{path}.{key}", depth + 1, flag_mode=flag_mode)
        elif kind == "Intent":
            if value is not None:
                validate_intent(value, f"{path}.{key}", depth + 1, flag_mode=flag_mode)
        elif kind == "Uri":
            string(value, f"{path}.{key}", nullable=True)
        elif kind in ("String[]", "boolean[]", "byte[]", "short[]", "int[]", "long[]", "float[]", "double[]", "char[]", "Intent[]"):
            if value is not None:
                if not isinstance(value, list):
                    raise SenderError(f"{path}.{key}: expected list")
                for index, element in enumerate(value):
                    typed_values({str(index): {"type": kind[:-2], "value": element}}, f"{path}.{key}", depth + 1,
                                 flag_mode=flag_mode)
        else:
            raise SenderError(f"{path}.{key}: unsupported type {kind!r}")


def validate_intent(intent, path="intent", depth=0, *, flag_mode=None):
    if depth > 8:
        raise SenderError(f"{path}: nesting exceeds 8 levels")
    fields(intent, ("component", "package", "action", "data", "mimeType", "flags",
                    "categories", "extras", "selector", "clipData"), path)
    for key in ("component", "package", "action", "data", "mimeType"):
        if key in intent:
            string(intent[key], f"{path}.{key}", nullable=True)
    if intent.get("component") is not None:
        if not intent["component"] or intent["component"].strip() != intent["component"]:
            raise SenderError(f"{path}.component: use a component name or null")
        try:
            intent["component"] = normalize_component(intent["component"])
        except ValueError as error:
            raise SenderError(str(error)) from None
    if intent.get("package") is not None and intent.get("selector") is not None:
        raise SenderError(f"{path}: package and selector cannot both be set")
    if "flags" in intent:
        mask = intent_flag_mask(intent["flags"], f"{path}.flags", allow_names=flag_mode is not None)
        if flag_mode == "mask":
            intent["flags"] = mask
    categories = intent.get("categories", [])
    if not isinstance(categories, list) or not all(isinstance(v, str) for v in categories):
        raise SenderError(f"{path}.categories: expected list of strings")
    if len(set(categories)) != len(categories):
        # Android keeps categories in a set: a repeated one would be dropped on the device.
        raise SenderError(f"{path}.categories: duplicate category")
    if intent.get("extras") is not None:
        typed_values(intent["extras"], f"{path}.extras", depth, flag_mode=flag_mode)
    if intent.get("selector") is not None:
        validate_intent(intent["selector"], f"{path}.selector", depth + 1, flag_mode=flag_mode)
    clip = intent.get("clipData")
    if clip is not None:
        fields(clip, ("label", "mimeTypes", "items"), f"{path}.clipData")
        string(clip.get("label"), path, nullable=True)
        if not isinstance(clip.get("mimeTypes"), list) or not clip["mimeTypes"] or not all(
                isinstance(v, str) and v for v in clip["mimeTypes"]):
            raise SenderError(f"{path}.clipData.mimeTypes: expected nonempty list")
        if not isinstance(clip.get("items"), list) or not clip["items"]:
            raise SenderError(f"{path}.clipData.items: at least one item is required")
        for item in clip["items"]:
            fields(item, ("text", "htmlText", "uri", "intent"), path)
            for key in ("text", "htmlText", "uri"):
                if key in item:
                    string(item[key], path, nullable=True)
            if item.get("intent") is not None:
                validate_intent(item["intent"], path, depth + 1, flag_mode=flag_mode)


def validate_request(raw, *, for_execution=False):
    """Keep authored flag names for storage; resolve them only for the agent."""
    flag_mode = "mask" if for_execution else "preserve"
    def check_strings(value, depth=0):
        if depth > 32:
            raise SenderError("Request nesting exceeds 32 levels")
        if isinstance(value, str):
            string(value, "request")
        elif isinstance(value, dict):
            for key, child in value.items():
                string(key, "request key")
                check_strings(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                check_strings(child, depth + 1)
    check_strings(raw)
    try:
        encoded = json.dumps(raw, allow_nan=False, ensure_ascii=True)
    except (ValueError, TypeError, RecursionError):
        raise SenderError("Request must contain finite JSON values") from None
    if len(encoded) > MAX_REQUEST_BYTES:
        raise SenderError("Request exceeds 256 KiB")
    value = copy.deepcopy(raw)
    fields(value, ("operation", "intent", "receiverPermission", "uri", "projection",
                   "selection", "selectionArgs", "sortOrder", "values", "method", "arg",
                   "extras", "maxRows", "maxBytes"), "request")
    operation = value.get("operation")
    if operation not in OPERATIONS:
        raise SenderError("Unsupported Sender operation")
    if operation in INTENT_OPERATIONS:
        fields(value, ("operation", "intent", "receiverPermission"), "request")
        validate_intent(value.get("intent"), flag_mode=flag_mode)
        if "receiverPermission" in value:
            if operation not in ("sendBroadcast", "sendOrderedBroadcast"):
                raise SenderError("receiverPermission applies only to broadcasts")
            string(value["receiverPermission"], "receiverPermission", nullable=True)
        if operation == "startActivity":
            flags = value["intent"].get("flags", 0)
            mask = intent_flag_mask(flags, "intent.flags", allow_names=True)
            new_task = NAMED_INTENT_FLAGS["FLAG_ACTIVITY_NEW_TASK"]
            if not mask & new_task:
                hint = ('add "FLAG_ACTIVITY_NEW_TASK" to the list' if isinstance(flags, list)
                        else f"use {mask | new_task} to keep the existing bits")
                raise SenderError(f"startActivity requires FLAG_ACTIVITY_NEW_TASK from the sender application context; {hint}")
    else:
        allowed = {
            "query": ("projection", "selection", "selectionArgs", "sortOrder", "maxRows", "maxBytes"),
            "getType": (), "insert": ("values",), "update": ("values", "selection", "selectionArgs"),
            "delete": ("selection", "selectionArgs"), "call": ("method", "arg", "extras"),
            "openFileDescriptor": ("maxBytes",),
        }[operation]
        fields(value, ("operation", "uri", *allowed), "request")
        uri = value.get("uri")
        if not isinstance(uri, str) or not uri.startswith("content://") or not uri[10:].split("/")[0]:
            raise SenderError("uri: expected content://authority/path")
        for key in ("selection", "sortOrder", "arg"):
            if key in value:
                string(value[key], key, nullable=True)
        for key in ("projection", "selectionArgs"):
            if value.get(key) is not None:
                if not isinstance(value[key], list) or not all(isinstance(v, str) for v in value[key]):
                    raise SenderError(f"{key}: expected null or list of strings")
        if operation in ("insert", "update"):
            typed_values(value.get("values"), "values")
            if any(v["type"] not in ("String", "boolean", "byte", "short", "int", "long", "float", "double", "byte[]") for v in value["values"].values()):
                raise SenderError("ContentValues accepts scalar values only")
        if operation == "call":
            string(value.get("method"), "method")
            if value.get("extras") is not None:
                typed_values(value["extras"], "extras", flag_mode=flag_mode)
        if operation in ("query", "openFileDescriptor"):
            limits = (("maxRows", 100, 1000), ("maxBytes", 262144, 262144)) if operation == "query" else (("maxBytes", 65536, 262144),)
            for key, default, maximum in limits:
                number = value.setdefault(key, default)
                if type(number) is not int or not 1 <= number <= maximum:
                    raise SenderError(f"{key}: expected integer between 1 and {maximum}")
    return value


def render_sender_detail(record, current_revision=None):
    """Match noxen's section headings and aligned label/value details.

    A request shows its arguments. A run is shown result first, beside its
    request; what was sent is listed only when the request has changed since
    (the run's revision differs from `current_revision`).
    """
    from rich.text import Text
    from rich.pretty import Pretty
    from rich.console import Group
    from noxen.rendering import capture_datetime, format_capture_time

    def device_time(value):
        instant = capture_datetime(value)
        return format_capture_time(instant, precise=True) if instant is not None else None

    def section(title, rows):
        text = Text()
        text.append(f"[{title}]\n", style="bold")
        width = max((len(label) for label, _ in rows), default=0)
        for label, value in rows:
            text.append(f"  {label:<{width}} : ", style="dim")
            text.append("None" if value is None else str(value), style="none")
            text.append("\n")
        return text

    request = record["request"]
    described = [section("REQUEST", [("Name", record["name"]), ("Operation", request["operation"])])]
    arguments = [Text("[ARGUMENTS]", style="bold"),
                 Pretty({k: v for k, v in request.items() if k != "operation"}, expand_all=True, highlighter=lambda value: value)]
    if "sender" not in record:
        return Group(*described, *arguments)
    identity = record["sender"]
    rows = [("Run", f"#{record['id']}")] if "id" in record else []
    rows.append(("State", record["state"]))
    # Only what happened is listed.
    if record.get("error"):
        rows.append(("Error", record["error"]))
    if record.get("cancellationRequested"):
        rows.append(("Cancellation requested", True))
    activity_returned = request["operation"] == "startActivity" and record["state"] == "returned"
    if activity_returned:
        rows = [("State", "Call returned · Activity launch unverified") if row[0] == "State" else row for row in rows]
    if record.get("activityContext", {}).get("state") == "background":
        rows.append(("Sender at dispatch", "Background process · Android may block the launch"))
    outcome = [section("RESULT", rows)]
    if "result" in record and not activity_returned:
        outcome.append(Pretty(record["result"], expand_all=True, highlighter=lambda value: value))
    outcome.append(section("TIMING", [("Created (host)", record["createdAt"]), ("Started (device)", device_time(record.get("startedAt"))),
                                      ("Finished (device)", device_time(record.get("finishedAt"))), ("Duration (ms)", record.get("durationMs"))]))
    sender = [section("SENDER", [("Package", identity["package"]), ("UID", identity["uid"]),
                                 ("PID", identity["pid"]), ("Device", record["device"]),
                                 ("Target SDK", identity.get("targetSdk")), ("System app", identity.get("systemApp")),
                                 ("Packages for UID", ", ".join(identity.get("packagesForUid", [])))])]
    if identity.get("permissions"):
        sender.append(section("SENDER PERMISSIONS", [("Granted" if p["granted"] else "Not granted", p["name"])
                                                     for p in identity["permissions"]]))
    if current_revision is None or record["revision"] == current_revision:
        return Group(*outcome, *sender)
    note = Text("The request has changed since this run. It was sent as:\n", style="dim")
    return Group(*outcome, *sender, note, *described, *arguments)


def compare_sender_runs(left, right):
    from difflib import unified_diff
    keys = ("request", "sender", "state", "result", "error")
    def lines(run):
        snapshot = {key: run.get(key) for key in keys}
        if isinstance(snapshot["sender"], dict):
            snapshot["sender"] = {key: value for key, value in snapshot["sender"].items() if key != "observedAt"}
        return json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True).splitlines()
    chunks, size = [], 0
    truncated = False
    for line in unified_diff(lines(left), lines(right), fromfile=f"Run #{left['id']}", tofile=f"Run #{right['id']}", lineterm=""):
        if size + len(line) > 65536:
            truncated = True
            break
        chunks.append(line)
        size += len(line) + 1
    return {"left": left["id"], "right": right["id"], "diff": "\n".join(chunks), "truncated": truncated}
