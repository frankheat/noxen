"""Validated Monitor profiles. This catalog is independent of Intent hooks."""
import copy
import json
import re
import uuid

MAX_PROFILES = 32
MAX_HOOKS = 128
MAX_EVENTS = 2000
_CLASS = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$", re.ASCII)
_PRIMITIVES = {"boolean": "Z", "byte": "B", "char": "C", "short": "S",
               "int": "I", "long": "J", "float": "F", "double": "D"}


def argument_type(value):
    value = value.strip()
    depth = 0
    while value.endswith("[]"):
        depth += 1
        value = value[:-2]
    if depth:
        if depth > 8 or (value not in _PRIMITIVES and not _CLASS.fullmatch(value)) or value == "void":
            raise ValueError("Invalid array argument type")
        return "[" * depth + _PRIMITIVES.get(value, "L" + value + ";")
    if value.startswith("["):
        if not re.fullmatch(r"\[{1,8}(?:[ZBCSIJFD]|L[A-Za-z_$][\w.$]*;)", value):
            raise ValueError("Invalid array descriptor")
    elif value == "void" or not _CLASS.fullmatch(value):
        raise ValueError("Use Java argument types, e.g. java.lang.String, boolean or int[]")
    return value


def validate_hook(hook):
    if not isinstance(hook, dict):
        raise ValueError("Invalid hook")
    clazz, method = hook.get("class", ""), hook.get("method", "")
    if not isinstance(clazz, str) or len(clazz) > 256 or not _CLASS.fullmatch(clazz):
        raise ValueError("Enter a valid Java class name")
    if not isinstance(method, str) or not re.fullmatch(r"[A-Za-z_$][\w$]*", method, re.ASCII) or len(method) > 128:
        raise ValueError("Enter a method name (use $init for a constructor)")
    args = hook.get("args", [])
    if not isinstance(args, list) or len(args) > 32 or any(not isinstance(a, str) or len(a) > 256 for a in args):
        raise ValueError("Invalid argument types (maximum 32)")
    result = {"class": clazz, "method": method, "args": [argument_type(a) for a in args]}
    for field, default in (("captureArguments", True), ("captureReturn", True), ("captureStack", False)):
        value = hook.get(field, default)
        if type(value) is not bool:
            raise ValueError("Capture options must be booleans")
        result[field] = value
    return result


def signature(hook):
    return f"{hook['class']}.{hook['method']}({', '.join(hook['args'])})"


def default_profiles():
    methods = [("loadUrl", ["java.lang.String"]),
               ("loadUrl", ["java.lang.String", "java.util.Map"]),
               ("postUrl", ["java.lang.String", "[B"]),
               ("loadData", ["java.lang.String"] * 3),
               ("loadDataWithBaseURL", ["java.lang.String"] * 5),
               ("evaluateJavascript", ["java.lang.String", "android.webkit.ValueCallback"]),
               ("addJavascriptInterface", ["java.lang.Object", "java.lang.String"]),
               ("removeJavascriptInterface", ["java.lang.String"])]
    return [{"id": "webview", "name": "WebView", "enabled": False,
             "hooks": [validate_hook({"class": "android.webkit.WebView", "method": m, "args": a}) for m, a in methods]}]


def validate_profiles(profiles):
    if not isinstance(profiles, list) or len(profiles) > MAX_PROFILES:
        raise ValueError(f"Maximum {MAX_PROFILES} profiles")
    result, ids, names, count = [], set(), set(), 0
    for p in profiles:
        if not isinstance(p, dict):
            raise ValueError("Invalid profile")
        pid, name = p.get("id"), p.get("name")
        if not isinstance(pid, str) or not re.fullmatch(r"[\w-]{1,64}", pid, re.ASCII) or pid in ids:
            raise ValueError("Invalid or duplicate profile ID")
        if not isinstance(name, str) or not name.strip() or len(name) > 60 or any(ord(c) < 32 for c in name):
            raise ValueError("Profile name must contain 1–60 printable characters")
        name = name.strip()
        if name.casefold() in names:
            raise ValueError("A profile with this name already exists")
        hooks = p.get("hooks")
        if not isinstance(hooks, list) or type(p.get("enabled")) is not bool:
            raise ValueError("Invalid profile hooks or enabled state")
        hooks = [validate_hook(h) for h in hooks]
        if len({signature(h) for h in hooks}) != len(hooks):
            raise ValueError("This method overload already exists in the profile")
        count += len(hooks)
        if count > MAX_HOOKS:
            raise ValueError(f"Maximum {MAX_HOOKS} hooks across profiles")
        ids.add(pid)
        names.add(name.casefold())
        result.append({"id": pid, "name": name, "enabled": p["enabled"], "hooks": hooks})
    return result


def load_profiles(raw):
    if not raw:
        return default_profiles(), None
    try:
        return validate_profiles(json.loads(raw)), None
    except (ValueError, TypeError):
        return default_profiles(), "Saved Monitor profiles are invalid; loaded the default profile."


def new_profile(name):
    return {"id": uuid.uuid4().hex, "name": name, "enabled": False, "hooks": []}


def enabled_hooks(profiles):
    return [dict(copy.deepcopy(h), profile=p["id"], profileName=p["name"], index=i)
            for p in profiles if p["enabled"] for i, h in enumerate(p["hooks"])]


def display_value(value):
    if not isinstance(value, dict):
        return "unavailable"
    if value.get("captureError"):
        return "unavailable (capture failed)"
    if value.get("opaque"):
        return "opaque object"
    if value.get("type") == "void":
        return "void"
    text = json.dumps(value.get("value"), ensure_ascii=True)
    return text + (" (truncated)" if value.get("truncated") else "")


def event_detail(event):
    lines = ["[CALL]", f"  Profile : {', '.join(event.get('profiles', []))}",
             f"  Class   : {event.get('class', 'unknown')}",
             f"  Method  : {event.get('method', 'unknown')}({', '.join(event.get('types', []))})",
             f"  Thread  : {event.get('thread', 'unknown')}",
             f"  Outcome : {event.get('outcome', 'unknown')}"]
    if "arguments" in event:
        lines += ["", "[ARGUMENTS]"]
        for i, value in enumerate(event["arguments"]):
            lines.append(f"  {i} [{value.get('type', 'unknown')}] : {display_value(value)}")
        if not event["arguments"]:
            lines.append("  No arguments")
    if "result" in event:
        result = event["result"]
        lines += ["", "[RETURN]", f"  [{result.get('type', 'unknown')}] : {display_value(result)}"]
    if "exception" in event:
        lines += ["", "[EXCEPTION]", f"  {event['exception'].get('type', 'unknown')} (original exception propagated)"]
    if "stack" in event:
        stack = event["stack"]
        lines += ["", "[STACK]"] + (["  " + s for s in stack] if isinstance(stack, list) else ["  unavailable"])
    return "\n".join(lines)
