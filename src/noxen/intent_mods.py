import copy


IntentMod = tuple[str, str, str, str]
IntentModParseResult = tuple[IntentMod | None, str | None]


VALID_EXTRA_TYPES = frozenset({"int", "bool", "boolean", "float", "long", "string", "double"})

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
}


def java_type_display(java_type: str) -> str:
    """Return a compact display name for a Java type."""
    if not java_type:
        return "-"
    return java_type.replace("$", ".").rsplit(".", 1)[-1]


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
    original_intent = entry["original_intent"]
    original_extras = original_intent.get("extras") or {}

    info = entry["intent"] = dict(entry.get("intent") or {})
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
                info["flags"] = _current_flags(info) | flag
        elif mod_type == "flag_rem":
            flag = parse_flag_value(value)
            if flag is not None:
                info["flags"] = _current_flags(info) & ~flag
        elif mod_type == "extra_rem":
            info["extras"].pop(key, None)
        elif mod_type == "extra_add":
            java_type = original_extras.get(key, {}).get("type") or extra_type
            info["extras"][key] = {"type": java_type, "value": value}


def parse_flag_value(value: str) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _single_value_mod(parts: list[str], mod_type: str, usage: str) -> IntentModParseResult:
    if len(parts) < 2:
        return None, usage
    return (mod_type, "", parts[1], ""), None


def _flag_mod(parts: list[str], mod_type: str, usage: str) -> IntentModParseResult:
    if len(parts) < 2:
        return None, usage
    if parse_flag_value(parts[1]) is None:
        return None, "[red]Flag must be an integer[/red]"
    return (mod_type, "", parts[1], ""), None


def _extra_add_mod(parts: list[str]) -> IntentModParseResult:
    if len(parts) < 3:
        return None, "[red]Usage: +x (type) <key> <value>[/red]"

    possible_type = parts[1].lower()
    if possible_type in VALID_EXTRA_TYPES and len(parts) >= 4:
        return ("extra_add", parts[2], " ".join(parts[3:]), possible_type), None
    return ("extra_add", parts[1], " ".join(parts[2:]), "string"), None


def _current_flags(info: dict) -> int:
    return parse_flag_value(info.get("flags") or 0) or 0
