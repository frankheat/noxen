import copy
import re


IntentMod = tuple[str, str, str, str]
IntentModParseResult = tuple[IntentMod | None, str | None]


EXTRA_TYPE_OPTIONS = (
    ("String", "string"),
    ("Null string", "null"),
    ("Boolean", "bool"),
    ("Integer", "int"),
    ("Long", "long"),
    ("Float", "float"),
    ("Double", "double"),
    ("URI", "uri"),
    ("Component", "component"),
    ("Integer array", "int[]"),
    ("Long array", "long[]"),
    ("Float array", "float[]"),
    ("Double array", "double[]"),
    ("String array", "string[]"),
    ("Integer list", "int-list"),
    ("Long list", "long-list"),
    ("Float list", "float-list"),
    ("Double list", "double-list"),
    ("String list", "string-list"),
)

EXTRA_VALUE_PLACEHOLDERS = {
    "string": "hello",
    "null": "not used",
    "bool": "true",
    "int": "5",
    "long": "5000000000",
    "float": "3.14",
    "double": "3.1415926535",
    "uri": "content://example/items/1",
    "component": "com.example/.MainActivity",
    "int[]": "1,2,3",
    "long[]": "5000000000,6000000000",
    "float[]": "1.5,2.5,3.5",
    "double[]": "1.25,2.5,3.75",
    "string[]": r"one,two,comma\,inside",
    "int-list": "1,2,3",
    "long-list": "5000000000,6000000000",
    "float-list": "1.5,2.5,3.5",
    "double-list": "1.25,2.5,3.75",
    "string-list": r"one,two,comma\,inside",
}

VALID_EXTRA_TYPES = frozenset(value for _label, value in EXTRA_TYPE_OPTIONS)

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


def java_type_display(java_type: str) -> str:
    """Return a compact display name for a Java type."""
    if not java_type:
        return "-"
    return java_type.replace("$", ".").rsplit(".", 1)[-1]


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


def parse_intent_mod_command(parts: list[str]) -> IntentModParseResult:
    if not parts:
        return None, None

    command = parts[0].lower()
    if command == "action":
        return _single_value_mod(parts, "action", "[red]Usage: action <val>[/red]")
    if command == "data":
        return _single_value_mod(parts, "data", "[red]Usage: data <uri>[/red]")
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


def apply_mods_to_intent(intent: dict, mods: list[IntentMod]) -> dict:
    """Return an Intent snapshot with ordered modifications applied."""
    original_intent = copy.deepcopy(intent or {})
    original_extras = original_intent.get("extras") or {}
    info = copy.deepcopy(original_intent)
    info["categories"] = list(info.get("categories") or [])
    info["extras"] = dict(info.get("extras") or {})

    for mod_type, key, value, extra_type in mods:
        if mod_type == "action":
            info["action"] = value or None
        elif mod_type == "data":
            info["data"] = value or None
        elif mod_type == "cat_add":
            if value and value not in info["categories"]:
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

    for field in ("action", "data"):
        old_value = before.get(field) or ""
        new_value = after.get(field) or ""
        if new_value != old_value:
            mods.append((field, "", str(new_value), ""))

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
