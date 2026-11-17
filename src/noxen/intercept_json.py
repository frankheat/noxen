"""Edit a held Intent as JSON.

The editor shows the captured Intent in Sender's format. What the user changes
is turned back into the staged modifications the agent applies, so values that
could not be captured (and are not in the JSON) stay on the Intent untouched.
"""

import copy

from noxen.intent_mods import (
    NESTED_INTENT_FIELDS,
    apply_mods_to_intent,
    diff_intents,
    nested_intent_fields,
    nested_intents,
    nested_mod_path,
    normalize_component,
    parse_flag_value,
    split_extra_values,
    validate_extra_value,
)
from noxen.sender import SenderError, fields, string, typed_values
from noxen.sender_capture import _intent

SCALARS = ("component", "action", "data", "mimeType")
INTENT_KEYS = ("component", "package", "action", "data", "mimeType", "flags", "categories", "extras",
               "selector", "clipData")
NESTED_FIELDS = tuple(NESTED_INTENT_FIELDS.values())
# Sender types the agent can set on a held Intent, and the agent's name for each.
EXTRA_TYPES = {"String": "string", "boolean": "bool", "int": "int", "long": "long", "float": "float",
               "double": "double", "Uri": "uri", "String[]": "string[]", "int[]": "int[]",
               "long[]": "long[]", "float[]": "float[]", "double[]": "double[]"}
SETTABLE = ", ".join(EXTRA_TYPES)


def editable_intent(entry):
    """The held Intent as Sender-format JSON, and notes on what could not be captured."""
    notes = []
    try:
        intent = _intent((entry or {}).get("intent"), "intent", notes=notes)
    except (AttributeError, IndexError, KeyError, TypeError, ValueError):
        return {}, ["This capture is malformed and could not be read in full"]
    return intent, notes


def json_to_mods(captured, shown, edited):
    """Staged modifications that turn the held Intent into `edited`. Raises ValueError when they cannot.

    `captured` is the Intent as the agent reported it, `shown` the JSON the editor
    started from. Only what differs between `shown` and `edited` is changed; a value
    that is absent from both (it could not be captured) is not touched.
    """
    if edited == shown:
        return []
    try:
        return _json_to_mods(captured, shown, edited)
    except SenderError as error:  # A changed value has the wrong shape.
        raise ValueError(str(error)) from None


def _json_to_mods(captured, shown, edited):
    # Only what changed is checked: the capture itself may hold states Sender would not build.
    fields(edited, INTENT_KEYS, "intent")
    draft = copy.deepcopy(captured or {})
    # A field deleted from the JSON is cleared; one never shown (not captured in full) stays as it is.
    empty = {"flags": 0, "categories": [], "extras": {}}
    edited = {**{key: empty.get(key) for key in shown if key not in edited}, **edited}
    for key in SCALARS:
        if key in edited and edited[key] != shown.get(key):
            string(edited[key], f"intent.{key}", nullable=True)
            draft[key] = normalize_component(edited[key]) or None if key == "component" and edited[key] else edited[key]
    if edited.get("package", shown.get("package")) != shown.get("package"):
        raise ValueError("package cannot be changed on a held Intent")
    if "flags" in edited and edited["flags"] != shown.get("flags"):
        if type(edited["flags"]) is not int or not 0 <= edited["flags"] <= 0xFFFFFFFF:
            raise ValueError("intent.flags: expected unsigned 32-bit integer")
        draft["flags"] = edited["flags"]
    if "categories" in edited and edited["categories"] != shown.get("categories"):
        categories = edited["categories"]
        if not isinstance(categories, list) or not all(isinstance(value, str) for value in categories):
            raise ValueError("intent.categories: expected list of strings")
        if len(set(categories)) != len(categories):
            raise ValueError("intent.categories: duplicate category")
        draft["categories"] = list(categories)
    if not isinstance(edited.get("extras") or {}, dict):
        raise ValueError("intent.extras: expected keyed typed values")
    _extras(draft, shown.get("extras") or {}, edited.get("extras") or {})
    for key in ("selector", "clipData"):
        if key in edited or key in shown:
            _nested_field(draft, key, shown.get(key), edited.get(key), (key,))
    return diff_intents(captured or {}, draft)


def _extras(draft, shown, edited):
    extras = draft.setdefault("extras", {})
    for key in shown:
        if key not in edited:
            extras.pop(key, None)
    for key, item in edited.items():
        before = shown.get(key)
        if item == before:
            continue
        if before is not None and isinstance(item, dict) and before["type"] == item.get("type") \
                and item["type"] in ("Intent", "Bundle"):
            _nested_value(draft, before, item, ("extras", key))
            continue
        typed_values({key: item}, "intent.extras")
        extra_type, value = _agent_extra(key, item)
        mods = ([("extra_rem", key, "", "")] if key in extras else []) + [("extra_add", key, value, extra_type)]
        extras[key] = apply_mods_to_intent({"extras": {key: extras.get(key)} if key in extras else {}}, mods)["extras"][key]


def _agent_extra(key, item):
    """The agent's type and text for one typed value, or ValueError when it cannot set it."""
    kind, value = item["type"], item["value"]
    if kind not in EXTRA_TYPES:
        raise ValueError(f"extras.{key}: {kind} values cannot be set on a held Intent (supported: {SETTABLE})")
    if value is None:
        if kind != "String":
            raise ValueError(f"extras.{key}: only a String extra can be set to null")
        return "null", ""
    if kind.endswith("[]"):
        if any(element is None for element in value):
            raise ValueError(f"extras.{key}: array elements cannot be null on a held Intent")
        text = ",".join(_element(kind[:-2], element) for element in value)
        if not value:
            raise ValueError(f"extras.{key}: an empty array cannot be set on a held Intent")
    else:
        text = _element(kind, value)
    extra_type = EXTRA_TYPES[kind]
    if error := validate_extra_value(extra_type, text):
        raise ValueError(f"extras.{key}: {error}")
    return extra_type, text


def _element(kind, value):
    if kind == "boolean":
        return "true" if value else "false"
    if kind == "String":
        return value.replace("\\", "\\\\").replace(",", "\\,")
    return str(value)


def _nested_value(draft, before, after, path):
    """A changed Intent or Bundle extra: only fields of Intents inside it may change."""
    if after["type"] == "Intent":
        _nested_intent(draft, before["value"], after["value"], path)
        return
    old, new = before["value"] or {}, after["value"] or {}
    if set(old) != set(new) or (before["value"] is None) != (after["value"] is None):
        raise ValueError(f"{_label(path)}: keys inside a Bundle cannot be added or removed on a held Intent")
    for key in old:
        if old[key] == new[key]:
            continue
        if old[key]["type"] == new[key]["type"] and old[key]["type"] in ("Intent", "Bundle"):
            _nested_value(draft, old[key], new[key], (*path, key))
        else:
            raise ValueError(f"{_label((*path, key))}: values inside a Bundle cannot be changed on a held Intent")


def _nested_field(draft, key, before, after, path):
    """selector or clipData of the held Intent: only fields of the Intents they hold may change."""
    if before == after:
        return
    if before is None or after is None:
        raise ValueError(f"{key} cannot be added or removed on a held Intent")
    if key == "selector":
        _nested_intent(draft, before, after, path)
        return
    same = {name: before.get(name) == after.get(name) for name in ("label", "mimeTypes")}
    old_items, new_items = before.get("items") or [], after.get("items") or []
    if not all(same.values()) or len(old_items) != len(new_items):
        raise ValueError("clipData: only fields of the Intents in its items can be changed on a held Intent")
    for index, (old, new) in enumerate(zip(old_items, new_items)):
        if {k: v for k, v in old.items() if k != "intent"} != {k: v for k, v in new.items() if k != "intent"}:
            raise ValueError("clipData: only fields of the Intents in its items can be changed on a held Intent")
        if old.get("intent") != new.get("intent"):
            if old.get("intent") is None or new.get("intent") is None:
                raise ValueError("clipData: an item Intent cannot be added or removed on a held Intent")
            _nested_intent(draft, old["intent"], new["intent"], (*path, index))


def _nested_intent(draft, before, after, path):
    if before is None or after is None:
        raise ValueError(f"{_label(path)}: a nested Intent cannot be added or removed on a held Intent")
    fields(after, INTENT_KEYS, _label(path))
    others = set(before) | set(after)
    for key in sorted(others - set(NESTED_FIELDS)):
        if before.get(key) == after.get(key):
            continue
        if key == "extras" and before.get(key) is not None and after.get(key) is not None:
            _nested_value(draft, {"type": "Bundle", "value": before[key]}, {"type": "Bundle", "value": after[key]},
                          (*path, "extras"))
            continue
        if key in ("selector", "clipData"):
            _nested_field(draft, key, before.get(key), after.get(key), (*path, key))
            continue
        raise ValueError(f"{_label(path)}: inside a nested Intent only {', '.join(NESTED_FIELDS)} can be changed")
    node = dict(nested_intents(draft)).get(path)
    readable = nested_intent_fields(node)
    for field in NESTED_FIELDS:
        if before.get(field) == after.get(field):
            continue
        if field not in readable:
            raise ValueError(f"{_label(path)}.{field} was not captured in full and cannot be changed")
        value = after.get(field)
        string(value, f"{_label(path)}.{field}", nullable=True)
        node[field] = normalize_component(value) or None if field == "component" and value else value


def _label(path):
    return ".".join(str(part) for part in path)


def apply_mod_to_json(intent, mod):
    """A command typed while the editor is open, applied to the JSON. Raises ValueError when it cannot be shown."""
    kind, key, value, extra_type = mod
    intent = copy.deepcopy(intent)
    if kind == "component":
        intent["component"] = normalize_component(value) or None
    elif kind in ("action", "data", "mime"):
        intent["mimeType" if kind == "mime" else kind] = value or None
    elif kind in ("cat_add", "cat_rem"):
        categories = [c for c in intent.get("categories") or [] if c != value]
        intent["categories"] = categories + [value] if kind == "cat_add" else categories
    elif kind in ("flag_add", "flag_rem"):
        flag = parse_flag_value(value) & 0xFFFFFFFF
        flags = intent.get("flags") or 0
        intent["flags"] = flags | flag if kind == "flag_add" else flags & ~flag
    elif kind == "extra_rem":
        (intent.get("extras") or {}).pop(key, None)
    elif kind == "extra_add":
        intent["extras"] = dict(intent.get("extras") or {})
        intent["extras"][key] = _typed(key, value, extra_type)
    elif kind in NESTED_INTENT_FIELDS:
        node = _json_node(intent, nested_mod_path(key, extra_type))
        if node is None:
            raise ValueError("That nested Intent is not in the JSON")
        field = NESTED_INTENT_FIELDS[kind]
        node[field] = (normalize_component(value) if field == "component" else value) or None
    else:
        raise ValueError(f"{kind} cannot be applied in the JSON editor")
    return intent


def _typed(key, value, extra_type):
    """An agent extra written by a command, as a Sender typed value."""
    if extra_type == "null":
        return {"type": "String", "value": None}
    names = {agent: sender for sender, agent in EXTRA_TYPES.items()}
    if extra_type not in names:
        raise ValueError(f"A {extra_type} extra cannot be shown in the JSON editor; "
                         "press Escape to close it and stage the command instead")
    kind = names[extra_type]
    items = split_extra_values(value) if kind.endswith("[]") else [value]
    element = kind.removesuffix("[]")
    if element == "boolean":
        converted = [item.lower() in ("true", "t") or (item.lower() not in ("false", "f") and int(item, 0) != 0)
                     for item in items]
    elif element == "int":
        converted = [int(item, 0) for item in items]
    elif element == "long":
        converted = [str(int(item, 10)) for item in items]
    elif element in ("float", "double"):
        converted = [float(item.rstrip("fFdD")) for item in items]
    else:
        converted = items
    return {"type": kind, "value": converted if kind.endswith("[]") else converted[0]}


def _json_node(intent, path):
    """The JSON Intent at a captured nested path (as `nested_intents` names it), or None."""
    node, kind, parts = intent, "intent", list(path)
    while parts:
        part = parts.pop(0)
        if kind == "bundle":
            item = node.get(part) if isinstance(part, str) else None
            if not isinstance(item, dict):
                return None
            node, kind = item.get("value"), {"Intent": "intent", "Bundle": "bundle"}.get(item.get("type"))
        elif part == "extras":
            node, kind = node.get("extras"), "bundle"
        elif part == "selector":
            node = node.get("selector")
        elif part == "clipData" and parts:
            index, items = parts.pop(0), (node.get("clipData") or {}).get("items") or []
            node = items[index].get("intent") if isinstance(index, int) and 0 <= index < len(items) else None
        else:
            return None
        if not isinstance(node, dict) or kind is None:
            return None
    return node if kind == "intent" else None
