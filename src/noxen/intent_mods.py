import copy
import json
import re
from collections.abc import Sequence


# (type, key, value, extra type or nested path). For action, data and MIME type,
# nested ones included, a None value clears the field and "" sets an empty string.
IntentMod = tuple[str, str, str | None, str]
IntentModParseResult = tuple[IntentMod | None, str | None]

NESTED_INTENT_FIELDS = {
    "nested_component": "component",
    "nested_action": "action",
    "nested_data": "data",
    "nested_mime": "mimeType",
}


# Extra types the agent can set, as commands and the JSON editor name them.
VALID_EXTRA_TYPES = frozenset((
    "string", "null", "bool", "int", "long", "float", "double", "uri", "component",
    "int[]", "long[]", "float[]", "double[]", "string[]",
    "int-list", "long-list", "float-list", "double-list", "string-list",
))

EXTRA_TYPE_ALIASES = {
    "boolean": "bool",
    "null-string": "null",
    "string-null": "null",
    "component-name": "component",
    "integer": "int",
    "integer[]": "int[]",
    "integer-list": "int-list",
    # adb flag names are accepted without their leading dashes.
    "es": "string", "esn": "null", "ez": "bool", "ei": "int",
    "el": "long", "ef": "float", "ed": "double", "eu": "uri",
    "ecn": "component", "eia": "int[]", "ela": "long[]",
    "efa": "float[]", "eda": "double[]", "esa": "string[]",
    "eial": "int-list", "elal": "long-list", "efal": "float-list",
    "edal": "double-list", "esal": "string-list",
}

JAVA_TYPE_TO_SIMPLE = {
    "java.lang.String": "string",
    "java.lang.Integer": "int",
    "java.lang.Boolean": "bool",
    "java.lang.Long": "long",
    "java.lang.Float": "float",
    "java.lang.Double": "double",
    "java.lang.Short": "int",
    "java.lang.Byte": "int",
    "java.lang.Character": "string",
    "android.net.Uri": "uri",
    "android.content.ComponentName": "component",
    "[I": "int[]",
    "[J": "long[]",
    "[F": "float[]",
    "[D": "double[]",
    "[Ljava.lang.String;": "string[]",
}

EXTRA_TYPE_TO_JAVA = {
    "string": "java.lang.String",
    "null": "java.lang.String",
    "bool": "java.lang.Boolean",
    "int": "java.lang.Integer",
    "long": "java.lang.Long",
    "float": "java.lang.Float",
    "double": "java.lang.Double",
    "uri": "android.net.Uri",
    "component": "android.content.ComponentName",
    "int[]": "[I",
    "long[]": "[J",
    "float[]": "[F",
    "double[]": "[D",
    "string[]": "[Ljava.lang.String;",
    "int-list": "java.util.ArrayList",
    "long-list": "java.util.ArrayList",
    "float-list": "java.util.ArrayList",
    "double-list": "java.util.ArrayList",
    "string-list": "java.util.ArrayList",
}

_INTEGER_RANGES = {
    "int": (-(2 ** 31), 2 ** 31 - 1),
    "long": (-(2 ** 63), 2 ** 63 - 1),
}
_FLOAT_RE = re.compile(
    r"^[+-]?(?:(?:\d+(?:\.\d*)?)|(?:\.\d+))(?:[eE][+-]?\d+)?[fFdD]?$"
)


def normalize_extra_type(extra_type: str) -> str | None:
    value = str(extra_type or "").lower()
    value = value[2:] if value.startswith("--") else value
    value = EXTRA_TYPE_ALIASES.get(value, value)
    return value if value in VALID_EXTRA_TYPES else None


def validate_extra_value(extra_type: str, value: str) -> str | None:
    """Validate the textual form accepted by the agent for an adb-compatible extra."""
    canonical = normalize_extra_type(extra_type)
    if canonical is None:
        return f"Unknown extra type: {extra_type}"
    if canonical == "null":
        return None
    if canonical == "bool":
        text = str(value).lower()
        if text not in {"true", "t", "false", "f"}:
            try:
                _decode_android_int(text)
            except ValueError:
                return "Boolean value must be true, false, t, f, or an integer"
        return None
    if canonical == "component":
        package, separator, class_name = str(value).partition("/")
        if not separator or not package or not class_name:
            return "Component must use package/class syntax"
        return None
    if canonical in {"uri", "string"}:
        return None

    element_type = canonical.removesuffix("[]").removesuffix("-list")
    values = split_extra_values(str(value)) if canonical.endswith(("[]", "-list")) else [str(value)]
    if element_type == "string":
        return None
    if not values or any(item == "" for item in values):
        return f"{canonical} requires comma-separated values"
    for item in values:
        if element_type in _INTEGER_RANGES:
            try:
                number = _decode_android_int(item) if element_type == "int" else int(item, 10)
            except ValueError:
                return f"Invalid {element_type} value: {item}"
            low, high = _INTEGER_RANGES[element_type]
            if not low <= number <= high:
                return f"{element_type.capitalize()} value out of range: {item}"
        elif element_type in {"float", "double"}:
            normalized = item.strip()
            if normalized.lower() not in {"nan", "+nan", "-nan", "infinity", "+infinity", "-infinity"}:
                if not _FLOAT_RE.fullmatch(normalized):
                    return f"Invalid {element_type} value: {item}"
                try:
                    float(normalized.rstrip("fFdD"))
                except ValueError:
                    return f"Invalid {element_type} value: {item}"
    return None


def split_extra_values(value: str) -> list[str]:
    r"""Split a comma list, interpreting ``\,`` as a literal comma."""
    values = []
    current = []
    escaped = False
    for char in value:
        if escaped:
            if char not in {",", "\\"}:
                current.append("\\")
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ",":
            values.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    values.append("".join(current))
    return values


def _decode_android_int(value: str) -> int:
    """Mirror Java Integer.decode, as used by adb for --ei/--eia/--eial."""
    text = str(value).strip()
    sign = 1
    if text.startswith(("+", "-")):
        if text[0] == "-":
            sign = -1
        text = text[1:]
    if text.startswith(("0x", "0X")):
        radix, digits = 16, text[2:]
    elif text.startswith("#"):
        radix, digits = 16, text[1:]
    elif len(text) > 1 and text.startswith("0"):
        radix, digits = 8, text[1:]
    else:
        radix, digits = 10, text
    if not digits:
        raise ValueError(value)
    number = sign * int(digits, radix)
    if not -(2 ** 31) <= number <= 2 ** 31 - 1:
        raise ValueError(value)
    return number


def normalize_component(value: str) -> str:
    """Validate flattened syntax and expand Android's leading-dot class form."""
    value = value.strip()
    if not value:
        return ""
    package, separator, name = value.partition("/")
    if (not separator or not package or not name or name == "." or "/" in name
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError("Component must use package/class syntax, e.g. com.example/.MainActivity")
    return package + "/" + (package + name if name.startswith(".") else name)


def parse_intent_mod_command(parts: list[str]) -> IntentModParseResult:
    if not parts:
        return None, None

    command = parts[0].lower()
    if command == "component":
        if len(parts) != 2:
            return None, "[red]Usage: component <package/class> | component clear[/red]"
        try:
            value = "" if parts[1].lower() == "clear" else normalize_component(parts[1])
        except ValueError as error:
            return None, f"[red]{error}[/red]"
        return ("component", "", value, ""), None
    if command == "action":
        return _single_value_mod(parts, "action", "[red]Usage: action <val>[/red]")
    if command == "data":
        return _single_value_mod(parts, "data", "[red]Usage: data <uri>[/red]")
    if command == "mime":
        if len(parts) == 2 and parts[1].lower() == "clear":
            return ("mime", "", None, ""), None
        return _single_value_mod(
            parts,
            "mime",
            "[red]Usage: mime <type> | mime clear[/red]",
        )
    if command == "+cat":
        return _single_value_mod(parts, "cat_add", "[red]Usage: +cat <val>[/red]")
    if command == "-cat":
        return _single_value_mod(parts, "cat_rem", "[red]Usage: -cat <val>[/red]")
    if command == "+flag":
        return _flag_mod(parts, "flag_add", "[red]Usage: +flag <int>[/red]")
    if command == "-flag":
        return _flag_mod(parts, "flag_rem", "[red]Usage: -flag <int>[/red]")
    if command == "+x":
        return _extra_add_mod(parts)
    if command == "-x":
        if len(parts) < 2:
            return None, "[red]Usage: -x <key>[/red]"
        return ("extra_rem", parts[1], "", ""), None
    return None, None


def apply_mods_to_entry(entry: dict, mods: list[IntentMod]) -> None:
    """Apply staged intent modifications to a stored History entry."""
    if not mods:
        return

    entry["original_intent"] = copy.deepcopy(entry.get("intent") or {})
    entry["intent"] = apply_mods_to_intent(entry["original_intent"], mods)


def confirmed_modification(
    original: dict, report: dict | None, *, require_component=False, mods: Sequence[IntentMod] = (),
) -> tuple[dict | None, bool, str | None]:
    """Return the agent-observed Intent, actual change flag, and any warning.

    A missing result is never replaced by a prediction from the requested mods.
    """
    actual = report.get("infoIntent") if isinstance(report, dict) else None
    required = {"action", "data", "mimeType", "flags", "categories", "extras"}
    if require_component or "component" in original:
        required.add("component")
    if not isinstance(actual, dict) or not required.issubset(actual):
        return None, False, "Resulting Intent could not be verified; requested changes are not shown as applied"
    if actual.get("component") is not None and not isinstance(actual["component"], str):
        return None, False, "Resulting Component could not be verified; requested changes are not shown as applied"

    expected = {
        (nested_mod_path(key, encoded_path), NESTED_INTENT_FIELDS[kind]):
            (value or None) if kind == "nested_component" else value
        for kind, key, value, encoded_path in mods if kind in NESTED_INTENT_FIELDS
    }
    observed_nodes = dict(nested_intents(actual)) if expected else {}
    actual = copy.deepcopy(actual)
    for field in ("selector", "clipData"):
        if field not in actual and field in original:
            actual[field] = copy.deepcopy(original[field])
    extras_meta = actual.get("extrasMeta")
    if not isinstance(extras_meta, dict):
        extras_meta = {}
    incomplete_extras = bool(extras_meta.get("error") or extras_meta.get("omitted"))
    warning = None
    incomplete_fields = set()
    for key in ("unreadableFields", "truncatedFields"):
        fields = actual.get(key)
        if isinstance(fields, list):
            incomplete_fields.update(field for field in fields if isinstance(field, str))
    for field in incomplete_fields & {"component", "action", "data", "mimeType", "package"}:
        actual[field] = copy.deepcopy(original.get(field))
        warning = "Resulting string fields could not be fully verified"
    if incomplete_extras:
        actual["extras"] = copy.deepcopy(original.get("extras", {}))
        warning = "Resulting extras could not be fully verified" if warning is None else (
            warning + "; resulting extras could not be fully verified"
        )
    if actual.get("categoriesTruncated") or actual.get("categoriesReadError"):
        actual["categories"] = copy.deepcopy(original.get("categories", []))
        warning = "Resulting categories could not be fully verified" if warning is None else (
            warning + "; resulting categories could not be fully verified"
        )

    def comparable(info: dict, field: str):
        if field == "flags":
            return info.get(field) or 0
        if field == "categories":
            return info.get(field) or []
        if field == "extras":
            return info.get(field) or {}
        if field in {"action", "data", "mimeType"}:
            return info.get(field)
        return info.get(field) or None

    changed = any(
        comparable(original, field) != comparable(actual, field)
        for field in ("component", "package", "action", "data", "mimeType", "flags", "categories", "extras",
                      "selector", "clipData")
    )
    if not report.get("ok"):
        detail = str(report.get("error") or "unknown agent error")
        warning = f"Modification failed; Intent may be partially changed: {detail}"
    elif expected:
        for (path, field), value in expected.items():
            fields = nested_intent_fields(observed_nodes.get(path))
            if field not in fields or fields[field] != value:
                detail = f"Could not verify {field} at {nested_intent_path_label(path)}"
                warning = f"{warning}; {detail}" if warning else detail
                break
    return actual, changed, warning


def nested_intent_fields(node: dict | None) -> dict:
    if (not isinstance(node, dict) or node.get("kind") != "intent"
            or node.get("type") != "android.content.Intent"):
        return {}
    return {
        field: node[field] for field in NESTED_INTENT_FIELDS.values()
        if field in node and not node.get(f"{field}Truncated")
        and (node[field] is None or isinstance(node[field], str))
    }


def nested_intents(intent):
    """Yield captured Intent nodes with unambiguous paths through supported containers."""
    def walk(node, path):
        if not isinstance(node, dict):
            return
        kind = node.get("kind")
        if kind == "intent" and node.get("type") == "android.content.Intent":
            yield path, node
            for field in ("extras", "selector", "clipData"):
                yield from walk(node.get(field), (*path, field))
        elif kind == "bundle" and node.get("type") == "android.os.Bundle":
            for item in node.get("items") or []:
                if not isinstance(item, dict):
                    continue
                key = item.get("key")
                if isinstance(key, str) and not item.get("keyTruncated"):
                    yield from walk(item.get("value"), (*path, key))
        elif kind == "clipdata":
            for index, item in enumerate(node.get("items") or []):
                if isinstance(item, dict) and item.get("kind") == "clipitem":
                    yield from walk(item.get("intent"), (*path, index))

    for key, extra in (intent.get("extras") or {}).items():
        if isinstance(extra, dict) and not extra.get("keyTruncated"):
            yield from walk(extra.get("structured"), ("extras", key))
    for field in ("selector", "clipData"):
        yield from walk(intent.get(field), (field,))


def nested_intent_path_label(path):
    return " → ".join(json.dumps(part, ensure_ascii=False) if isinstance(part, str) else f"Item {part}"
                      for part in path)


def nested_mod_path(key, encoded_path):
    return tuple(json.loads(encoded_path)) if encoded_path else ("extras", key)


def apply_mods_to_intent(intent: dict, mods: list[IntentMod]) -> dict:
    """Return an Intent snapshot with ordered modifications applied."""
    original_intent = copy.deepcopy(intent or {})
    original_extras = original_intent.get("extras") or {}
    info = copy.deepcopy(original_intent)
    info["categories"] = list(info.get("categories") or [])
    info["extras"] = dict(info.get("extras") or {})

    for mod_type, key, value, extra_type in mods:
        if mod_type == "component":
            info["component"] = normalize_component(value) or None
        elif mod_type == "action":
            info["action"] = value
        elif mod_type == "data":
            info["data"] = value
        elif mod_type == "mime":
            info["mimeType"] = value
        elif mod_type == "cat_add":
            if value not in info["categories"]:
                info["categories"].append(value)
        elif mod_type == "cat_rem":
            info["categories"] = [category for category in info["categories"] if category != value]
        elif mod_type == "flag_add":
            flag = parse_flag_value(value)
            if flag is not None:
                info["flags"] = (_current_flags(info) | flag) & 0xFFFFFFFF
        elif mod_type == "flag_rem":
            flag = parse_flag_value(value)
            if flag is not None:
                info["flags"] = (_current_flags(info) & ~flag) & 0xFFFFFFFF
        elif mod_type == "extra_rem":
            info["extras"].pop(key, None)
        elif mod_type in NESTED_INTENT_FIELDS:
            field = NESTED_INTENT_FIELDS[mod_type]
            node = dict(nested_intents(info)).get(nested_mod_path(key, extra_type))
            if field in nested_intent_fields(node):
                node[field] = normalize_component(value or "") or None if field == "component" else value
        elif mod_type == "extra_add":
            canonical = normalize_extra_type(extra_type) or "string"
            existing = original_extras.get(key, {})
            java_type = existing.get("type") if existing.get("noxenType") == canonical else None
            info["extras"][key] = {
                "type": java_type or EXTRA_TYPE_TO_JAVA[canonical],
                "value": None if canonical == "null" else value,
                "noxenType": canonical,
            }
    return info


def diff_intents(original: dict, draft: dict) -> list[IntentMod]:
    """Build ordered modifications that turn an original snapshot into a draft."""
    before = original or {}
    after = draft or {}
    mods: list[IntentMod] = []

    old_component = before.get("component") or ""
    new_component = normalize_component(after.get("component") or "")
    try:
        old_component = normalize_component(old_component)
    except ValueError:
        pass  # A malformed legacy value can still be cleared or replaced.
    if old_component != new_component:
        mods.append(("component", "", new_component, ""))

    for field, mod_type in (("action", "action"), ("data", "data"), ("mimeType", "mime")):
        old_value = before.get(field)
        new_value = after.get(field)
        if new_value != old_value:
            mods.append((mod_type, "", None if new_value is None else str(new_value), ""))

    old_categories = list(before.get("categories") or [])
    new_categories = list(after.get("categories") or [])
    for category in old_categories:
        if category not in new_categories:
            mods.append(("cat_rem", "", category, ""))
    for category in new_categories:
        if category not in old_categories:
            mods.append(("cat_add", "", category, ""))

    old_flags = _current_flags(before)
    new_flags = _current_flags(after)
    if new_flags != old_flags:
        if old_flags:
            mods.append(("flag_rem", "", str(old_flags), ""))
        if new_flags:
            mods.append(("flag_add", "", str(new_flags), ""))

    old_extras = before.get("extras") or {}
    new_extras = after.get("extras") or {}
    for key in old_extras:
        if key not in new_extras:
            mods.append(("extra_rem", key, "", ""))
    for key, extra in new_extras.items():
        old_extra = old_extras.get(key)
        if old_extra == extra:
            continue
        canonical = normalize_extra_type(
            extra.get("noxenType") or JAVA_TYPE_TO_SIMPLE.get(extra.get("type") or "")
        )
        if canonical is None:
            # Opaque values are read-only in the editor. They can disappear from the
            # draft, but cannot be reconstructed safely from their display string.
            continue
        if old_extra is not None:
            mods.append(("extra_rem", key, "", ""))
        value = "" if extra.get("value") is None else str(extra.get("value"))
        mods.append(("extra_add", key, value, canonical))

    old_nodes = dict(nested_intents(before))
    for path, node in nested_intents(after):
        old_fields = nested_intent_fields(old_nodes.get(path))
        new_fields = nested_intent_fields(node)
        direct = len(path) == 2 and path[0] == "extras"
        key, encoded_path = (path[1], "") if direct else ("", json.dumps(path))
        for kind, field in NESTED_INTENT_FIELDS.items():
            if field in old_fields and field in new_fields and old_fields[field] != new_fields[field]:
                value = new_fields[field]
                if field == "component":
                    value = normalize_component(value or "")
                mods.append((kind, key, value, encoded_path))
    return mods


def parse_flag_value(value: str) -> int | None:
    try:
        parsed = int(str(value), 0)
    except (TypeError, ValueError):
        return None
    # Intent flags are a Java int. Accept its signed range and the equivalent
    # unsigned bit-mask notation commonly used for Android flags.
    return parsed if -(1 << 31) <= parsed <= (1 << 32) - 1 else None


def _single_value_mod(parts: list[str], mod_type: str, usage: str) -> IntentModParseResult:
    if len(parts) < 2:
        return None, usage
    return (mod_type, "", parts[1], ""), None


def _flag_mod(parts: list[str], mod_type: str, usage: str) -> IntentModParseResult:
    if len(parts) < 2:
        return None, usage
    if parse_flag_value(parts[1]) is None:
        return None, "[red]Flag must be a 32-bit integer or bit mask[/red]"
    return (mod_type, "", parts[1], ""), None


def _extra_add_mod(parts: list[str]) -> IntentModParseResult:
    if len(parts) < 3:
        return None, "[red]Usage: +x [type] <key> <value>[/red]"

    possible_type = normalize_extra_type(parts[1])
    if possible_type == "null":
        if len(parts) != 3:
            return None, "[red]Usage: +x null <key>[/red]"
        return ("extra_add", parts[2], "", "null"), None
    if possible_type is not None:
        if len(parts) < 4:
            return None, "[red]Usage: +x [type] <key> <value>[/red]"
        value = " ".join(parts[3:])
        error = validate_extra_value(possible_type, value)
        if error:
            return None, f"[red]{error}[/red]"
        return ("extra_add", parts[2], value, possible_type), None
    return ("extra_add", parts[1], " ".join(parts[2:]), "string"), None


def _current_flags(info: dict) -> int:
    parsed = parse_flag_value(info.get("flags") or 0)
    return 0 if parsed is None else parsed & 0xFFFFFFFF
