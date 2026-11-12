"""Validated Monitor profiles. This catalog is independent of Intent hooks."""
import copy
import json
import re
import uuid

from rich.text import Text

from noxen.rendering import format_uri_grant_flags

MAX_PROFILES = 32
MAX_HOOKS = 128
PROFILE_FORMAT_VERSION = 10
_RESOLVER = "android.content.ContentResolver"
_SQLITE = "android.database.sqlite.SQLiteDatabase"
_ANDROID_LOG = "android.util.Log"
_PREFERENCES_EDITOR = "android.app.SharedPreferencesImpl$EditorImpl"
_URL = "java.net.URL"
_SOCKET = "java.net.Socket"
_CIPHER = "javax.crypto.Cipher"
_RUNTIME = "java.lang.Runtime"
_PROCESS_BUILDER = "java.lang.ProcessBuilder"
_DEX_CLASS_LOADER = "dalvik.system.DexClassLoader"
_IN_MEMORY_DEX_CLASS_LOADER = "dalvik.system.InMemoryDexClassLoader"
_CLASS_LOADER = "java.lang.ClassLoader"
_BYTE_BUFFER = "java.nio.ByteBuffer"
_BYTE_BUFFERS = "[Ljava.nio.ByteBuffer;"
_PACKAGE_CONTEXT_FLAGS = {1: "CONTEXT_INCLUDE_CODE", 2: "CONTEXT_IGNORE_SECURITY", 4: "CONTEXT_RESTRICTED"}
_WEBVIEW = "android.webkit.WebView"
_WEB_SETTINGS = "android.webkit.WebSettings"
_WEB_SETTING_LABELS = {
    "setJavaScriptEnabled": "JavaScript",
    "setAllowFileAccess": "File access",
    "setAllowContentAccess": "Content URI access",
    "setAllowFileAccessFromFileURLs": "File access from file URLs",
    "setAllowUniversalAccessFromFileURLs": "Universal access from file URLs",
    "setMixedContentMode": "Mixed content",
}
_MIXED_CONTENT_MODES = {0: "ALWAYS_ALLOW", 1: "NEVER_ALLOW", 2: "COMPATIBILITY_MODE"}
_CIPHER_MODES = {1: "ENCRYPT", 2: "DECRYPT", 3: "WRAP", 4: "UNWRAP"}
_KEY = "java.security.Key"
_CERTIFICATE = "java.security.cert.Certificate"
_PARAMETERS = ("java.security.spec.AlgorithmParameterSpec", "java.security.AlgorithmParameters")
_SECURE_RANDOM = "java.security.SecureRandom"
_LOG_LEVELS = {"v": "VERBOSE", "d": "DEBUG", "i": "INFO", "w": "WARN", "e": "ERROR", "wtf": "WTF"}
_LOG_PRIORITIES = dict(enumerate(("VERBOSE", "DEBUG", "INFO", "WARN", "ERROR", "ASSERT"), start=2))
_CONTEXT_IMPL = "android.app.ContextImpl"
_URI = "android.net.Uri"
_STRING = "java.lang.String"
_PREFERENCE_EDITS = {
    "putString": [_STRING, _STRING],
    "putStringSet": [_STRING, "java.util.Set"],
    "putBoolean": [_STRING, "boolean"],
    "putInt": [_STRING, "int"],
    "putLong": [_STRING, "long"],
    "putFloat": [_STRING, "float"],
    "remove": [_STRING],
    "clear": [],
}
_THROWABLE = "java.lang.Throwable"
_FILE = "java.io.File"
_FILES = "java.nio.file.Files"
_PATH = "java.nio.file.Path"
_COPY_OPTIONS = "[Ljava.nio.file.CopyOption;"
_CONTENT_VALUES = "android.content.ContentValues"
_FILE_INPUT = "java.io.FileInputStream"
_FILE_OUTPUT = "java.io.FileOutputStream"
_RANDOM_FILE = "java.io.RandomAccessFile"
_STRINGS = "[Ljava.lang.String;"
_BUNDLE = "android.os.Bundle"
_CANCEL = "android.os.CancellationSignal"
_LEGACY_QUERY = [_URI, _STRINGS, _STRING, _STRINGS, _STRING]
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


def missing_default_hooks(profile):
    if profile is None:
        return []
    default = next((p for p in default_profiles() if p["id"] == profile["id"]), None)
    if default is None:
        return []
    present = {signature(hook) for hook in profile["hooks"]}
    return [hook for hook in default["hooks"] if signature(hook) not in present]


def default_profiles():
    methods = [("loadUrl", ["java.lang.String"]),
               ("loadUrl", ["java.lang.String", "java.util.Map"]),
               ("postUrl", ["java.lang.String", "[B"]),
               ("loadData", ["java.lang.String"] * 3),
               ("loadDataWithBaseURL", ["java.lang.String"] * 5),
               ("evaluateJavascript", ["java.lang.String", "android.webkit.ValueCallback"]),
               ("addJavascriptInterface", ["java.lang.Object", "java.lang.String"]),
               ("removeJavascriptInterface", ["java.lang.String"])]
    resolver_methods = [
        ("query", _LEGACY_QUERY),
        ("query", [*_LEGACY_QUERY, _CANCEL]),
        ("query", [_URI, _STRINGS, _BUNDLE, _CANCEL]),
        ("call", [_URI, _STRING, _STRING, _BUNDLE]),
        ("call", [_STRING, _STRING, _STRING, _BUNDLE]),
        ("insert", [_URI, _CONTENT_VALUES]),
        ("insert", [_URI, _CONTENT_VALUES, _BUNDLE]),
        ("update", [_URI, _CONTENT_VALUES, _STRING, _STRINGS]),
        ("update", [_URI, _CONTENT_VALUES, _BUNDLE]),
        ("delete", [_URI, _STRING, _STRINGS]),
        ("delete", [_URI, _BUNDLE]),
        ("openInputStream", [_URI]),
        ("openOutputStream", [_URI]),
        ("openOutputStream", [_URI, _STRING]),
        ("openFileDescriptor", [_URI, _STRING]),
        ("openFileDescriptor", [_URI, _STRING, _CANCEL]),
        ("openTypedAssetFileDescriptor", [_URI, _STRING, _BUNDLE]),
        ("openTypedAssetFileDescriptor", [_URI, _STRING, _BUNDLE, _CANCEL]),
    ]
    profiles = [
        {"id": pid, "name": name, "enabled": False,
         "hooks": [validate_hook({"class": clazz, "method": method, "args": args})
                   for method, args in definitions]}
        for pid, name, clazz, definitions in (
            ("webview", "WebView", _WEBVIEW, methods),
            ("content-provider", "Content Provider", _RESOLVER, resolver_methods),
        )
    ]
    profiles[0]["hooks"].append(validate_hook({
        "class": _WEBVIEW, "method": "getSettings", "captureReturn": False,
    }))
    profiles[0]["hooks"].extend(
        validate_hook({
            "class": _WEB_SETTINGS, "method": method,
            "args": ["int" if method == "setMixedContentMode" else "boolean"], "captureReturn": False,
        })
        for method in _WEB_SETTING_LABELS
    )
    profiles.append({
        "id": "uri-grants", "name": "URI Grants", "enabled": False,
        "hooks": [
            validate_hook({"class": clazz, "method": method, "args": args})
            for clazz, method, args in (
                (_CONTEXT_IMPL, "grantUriPermission", [_STRING, _URI, "int"]),
                (_CONTEXT_IMPL, "revokeUriPermission", [_URI, "int"]),
                (_CONTEXT_IMPL, "revokeUriPermission", [_STRING, _URI, "int"]),
                (_RESOLVER, "takePersistableUriPermission", [_URI, "int"]),
                (_RESOLVER, "releasePersistableUriPermission", [_URI, "int"]),
            )
        ],
    })
    profiles.append({
        "id": "file", "name": "File", "enabled": False,
        "hooks": [
            validate_hook({"class": clazz, "method": "$init", "args": [path_type, *tail],
                           "captureReturn": False})
            for clazz, tails in (
                (_FILE_INPUT, [()]),
                (_FILE_OUTPUT, [(), ("boolean",)]),
                (_RANDOM_FILE, [(_STRING,)]),
            )
            for path_type in (_STRING, _FILE)
            for tail in tails
        ] + [
            validate_hook({"class": clazz, "method": method, "args": args})
            for clazz, method, args in (
                (_FILE, "delete", []),
                (_FILE, "renameTo", [_FILE]),
                (_FILES, "copy", [_PATH, _PATH, _COPY_OPTIONS]),
                (_FILES, "move", [_PATH, _PATH, _COPY_OPTIONS]),
            )
        ],
    })
    profiles.append({
        "id": "sqlite", "name": "SQLite", "enabled": False,
        "hooks": [
            validate_hook({"class": _SQLITE, "method": method, "args": args})
            for method, args in (
                ("rawQueryWithFactory", [_SQLITE + "$CursorFactory", _STRING, _STRINGS, _STRING, _CANCEL]),
                ("execSQL", [_STRING]),
                ("execSQL", [_STRING, "[Ljava.lang.Object;"]),
            )
        ],
    })
    log_methods = [
        (method, args)
        for method in _LOG_LEVELS
        for args in ([_STRING, _STRING], [_STRING, _STRING, _THROWABLE])
    ]
    log_methods += [
        ("w", [_STRING, _THROWABLE]),
        ("wtf", [_STRING, _THROWABLE]),
        ("println", ["int", _STRING, _STRING]),
    ]
    profiles.append({
        "id": "android-log", "name": "Android Log", "enabled": False,
        "hooks": [
            validate_hook({"class": _ANDROID_LOG, "method": method, "args": args})
            for method, args in log_methods
        ],
    })
    profiles.append({
        "id": "shared-preferences", "name": "SharedPreferences", "enabled": False,
        "hooks": [
            validate_hook({"class": _PREFERENCES_EDITOR, "method": method, "args": args,
                           "captureReturn": method == "commit"})
            for method, args in {**_PREFERENCE_EDITS, "apply": [], "commit": []}.items()
        ],
    })
    profiles.append({
        "id": "java-network", "name": "Java Network", "enabled": False,
        "hooks": [
            validate_hook({"class": clazz, "method": method, "args": args})
            for clazz, method, args in (
                (_URL, "openConnection", []),
                (_URL, "openConnection", ["java.net.Proxy"]),
                (_SOCKET, "connect", ["java.net.SocketAddress", "int"]),
            )
        ],
    })
    cipher_methods = [
        ("getInstance", args) for args in ([_STRING], [_STRING, _STRING], [_STRING, "java.security.Provider"])
    ]
    cipher_methods.extend(
        ("init", ["int", *args, *random])
        for args in ([_KEY], [_CERTIFICATE], *([_KEY, parameter] for parameter in _PARAMETERS))
        for random in ([], [_SECURE_RANDOM])
    )
    profiles.append({
        "id": "crypto", "name": "Crypto", "enabled": False,
        "hooks": [
            validate_hook({"class": _CIPHER, "method": method, "args": args,
                           "captureReturn": method == "getInstance"})
            for method, args in cipher_methods
        ],
    })
    profiles.append({
        "id": "process-execution", "name": "Process Execution", "enabled": False,
        "hooks": [
            validate_hook({"class": _RUNTIME, "method": "exec", "args": [command, *tail]})
            for command in (_STRING, _STRINGS)
            for tail in ([], [_STRINGS], [_STRINGS, _FILE])
        ] + [validate_hook({"class": _PROCESS_BUILDER, "method": "start"})],
    })
    profiles.append({
        "id": "dynamic-code-loading", "name": "Dynamic Code Loading", "enabled": False,
        "hooks": [
            validate_hook({"class": clazz, "method": method, "args": args,
                           "captureReturn": method != "$init"})
            for clazz, method, args in (
                (_DEX_CLASS_LOADER, "$init", [_STRING, _STRING, _STRING, _CLASS_LOADER]),
                (_IN_MEMORY_DEX_CLASS_LOADER, "$init", [_BYTE_BUFFER, _CLASS_LOADER]),
                (_IN_MEMORY_DEX_CLASS_LOADER, "$init", [_BYTE_BUFFERS, _CLASS_LOADER]),
                (_IN_MEMORY_DEX_CLASS_LOADER, "$init", [_BYTE_BUFFERS, _STRING, _CLASS_LOADER]),
                (_CONTEXT_IMPL, "createPackageContext", [_STRING, "int"]),
            )
        ],
    })
    return profiles


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
        saved = json.loads(raw)
        if isinstance(saved, list):
            profiles, new_defaults = validate_profiles(saved), default_profiles()[1:]
        elif isinstance(saved, dict):
            version = saved.get("version")
            if type(version) is not int or not 1 <= version <= PROFILE_FORMAT_VERSION:
                raise ValueError("Unsupported Monitor profile format")
            profiles = validate_profiles(saved.get("profiles"))
            if version == PROFILE_FORMAT_VERSION:
                return profiles, None
            new_defaults = default_profiles()[version + 1:]
        else:
            raise ValueError("Unsupported Monitor profile format")
        # Add only profiles introduced since this project was saved.
        for default in new_defaults:
            if any(p["id"] == default["id"] or p["name"].casefold() == default["name"].casefold()
                   for p in profiles):
                continue
            hook_count = sum(len(p["hooks"]) for p in profiles)
            if len(profiles) < MAX_PROFILES and hook_count + len(default["hooks"]) <= MAX_HOOKS:
                profiles.append(default)
        return profiles, None
    except (ValueError, TypeError):
        return default_profiles(), "Saved Monitor profiles are invalid; loaded the default profiles."


def new_profile(name):
    return {"id": uuid.uuid4().hex, "name": name, "enabled": False, "hooks": []}


def enabled_hooks(profiles):
    return [dict(copy.deepcopy(h), profile=p["id"], profileName=p["name"], index=i)
            for p in profiles if p["enabled"] for i, h in enumerate(p["hooks"])]


def event_method_label(event):
    method = event.get("method", "Capture error")
    if method == "$init" and event.get("class"):
        return event["class"].rsplit(".", 1)[-1]
    return method


def event_sort_value(event, column):
    if column == "time":
        return event.get("time", 0)
    if column == "profile":
        return ", ".join(event.get("profiles", [])).casefold()
    if column == "class":
        return (event.get("class") or "").casefold()
    if column == "method":
        return event_method_label(event).casefold()
    return event.get("outcome", "unknown").casefold()


def display_value(value):
    if not isinstance(value, dict):
        return "unavailable"
    if value.get("captureError"):
        return "unavailable (capture failed)"
    if type(remaining := value.get("remainingBytes")) is int:
        return f"{remaining} bytes remaining"
    if value.get("opaque"):
        return "opaque object"
    if value.get("type") == "void":
        return "void"
    raw = value.get("value")
    if value.get("type") == "long" and isinstance(raw, str) and re.fullmatch(r"-?[0-9]{1,19}", raw):
        return raw
    text = json.dumps(raw, ensure_ascii=True)
    return text + (" (truncated)" if value.get("truncated") else "")


def _argument_names(event):
    clazz = event.get("class")
    method, types = event.get("method"), event.get("types", [])
    if clazz == _WEB_SETTINGS and method in _WEB_SETTING_LABELS:
        return (_WEB_SETTING_LABELS[method],)
    if clazz == _DEX_CLASS_LOADER and method == "$init":
        return ("DEX path", "Optimized directory argument", "Native library path", "Parent loader")
    if clazz == _IN_MEMORY_DEX_CLASS_LOADER and method == "$init" and types:
        if types[0] == _BYTE_BUFFER:
            return ("DEX buffer", "Parent loader")
        if types == [_BYTE_BUFFERS, _STRING, _CLASS_LOADER]:
            return ("DEX buffers", "Native library path", "Parent loader")
        if types == [_BYTE_BUFFERS, _CLASS_LOADER]:
            return ("DEX buffers", "Parent loader")
    if clazz == _CONTEXT_IMPL and method == "createPackageContext" and types == [_STRING, "int"]:
        return ("Package", "Context flags")
    if clazz == _CIPHER:
        if method == "getInstance":
            return ("Transformation", "Requested provider")
        if method == "init":
            labels = {
                "int": "Mode",
                _KEY: "Key",
                _CERTIFICATE: "Certificate",
                _PARAMETERS[0]: "Parameter spec",
                _PARAMETERS[1]: "Parameters",
                _SECURE_RANDOM: "Random source",
            }
            return tuple(labels.get(arg, arg) for arg in types)
    if clazz == _URL and method == "openConnection":
        return ("Proxy",)
    if clazz == _SOCKET and method == "connect":
        return ("Endpoint", "Timeout (ms)")
    if clazz == _PREFERENCES_EDITOR and method in _PREFERENCE_EDITS and types == _PREFERENCE_EDITS[method]:
        return ("Key", "Value")[:len(types)]
    if clazz == _ANDROID_LOG:
        if method == "println":
            return ("Priority", "Tag", "Message")
        if method in _LOG_LEVELS:
            if types == [_STRING, _THROWABLE]:
                return ("Tag", "Throwable")
            return ("Tag", "Message", "Throwable")
    if clazz == _SQLITE:
        if method == "rawQueryWithFactory":
            return ("Cursor factory", "SQL", "Bindings", "Edit table", "Cancellation signal")
        if method == "execSQL":
            return ("SQL", "Bindings")
    if method == "$init" and types and types[0] in (_STRING, _FILE):
        if clazz == _FILE_INPUT:
            return ("Path",)
        if clazz == _FILE_OUTPUT:
            return ("Path", "Append")
        if clazz == _RANDOM_FILE:
            return ("Path", "Mode")
    if clazz == _FILE and method == "renameTo" and types == [_FILE]:
        return ("Destination",)
    if clazz == _FILES and method in ("copy", "move") and types == [_PATH, _PATH, _COPY_OPTIONS]:
        return ("Source", "Destination", "Options")
    if clazz == _CONTEXT_IMPL and method in ("grantUriPermission", "revokeUriPermission"):
        if types == [_STRING, _URI, "int"]:
            return ("Target package", "URI", "Mode flags")
        if method == "revokeUriPermission" and types == [_URI, "int"]:
            return ("URI", "Mode flags")
    if clazz != _RESOLVER:
        return ()
    if method in ("takePersistableUriPermission", "releasePersistableUriPermission") and types == [_URI, "int"]:
        return ("URI", "Mode flags")
    if method == "query":
        if len(types) == 4 and types[2] == _BUNDLE:
            return ("URI", "Projection", "Query arguments", "Cancellation signal")
        return ("URI", "Projection", "Selection", "Selection arguments", "Sort order", "Cancellation signal")
    if method == "call" and types:
        return ("URI" if types[0] == _URI else "Authority", "Command", "Argument", "Extras")
    if method == "insert":
        return ("URI", "Values", "Extras")
    if method == "update":
        if types == [_URI, _CONTENT_VALUES, _BUNDLE]:
            return ("URI", "Values", "Extras")
        return ("URI", "Values", "Selection", "Selection arguments")
    if method == "delete":
        if types == [_URI, _BUNDLE]:
            return ("URI", "Extras")
        return ("URI", "Selection", "Selection arguments")
    if method == "openFileDescriptor":
        return ("URI", "Mode", "Cancellation signal")
    if method == "openTypedAssetFileDescriptor":
        return ("URI", "MIME filter", "Options", "Cancellation signal")
    if method == "openOutputStream":
        return ("URI", "Mode")
    if method == "openInputStream":
        return ("URI",)
    return ()


def event_detail(event):
    return render_event_detail(event).plain


def render_event_detail(event) -> Text:
    text = Text(overflow="fold")

    def section(title):
        if text:
            text.append("\n\n")
        text.append(f"[{title}]", "bold")

    def field(label, value, suffix=""):
        text.append(f"\n  {label} :", "dim")
        text.append(f" {value}")
        text.append(suffix, "dim")

    def typed_value(indent, name, value, rendered):
        text.append(f"\n{indent}{name}")
        text.append(f"[{value.get('type', 'unknown')}]", "dim")
        text.append(" : ")
        if rendered in {"opaque object", "unavailable", "unavailable (capture failed)"}:
            text.append(rendered, "dim")
        elif rendered.endswith(" (truncated)"):
            text.append(rendered.removesuffix(" (truncated)"))
            text.append(" (truncated)", "dim")
        else:
            text.append(rendered)

    section("CALL")
    field("Profile", ", ".join(event.get("profiles", [])))
    field("Class  ", event.get("class", "unknown"))
    types = ", ".join(event.get("types", []))
    field("Method ", event.get("method", "unknown"), f"({types})")
    field("Thread ", event.get("thread", "unknown"))
    field("Outcome", event.get("outcome", "unknown"))
    if "webViewId" in event:
        field("WebView ID", event["webViewId"])
    if event.get("target"):
        field("Target ", event["target"])
    if event.get("class") == _ANDROID_LOG and event.get("method") in _LOG_LEVELS:
        field("Level  ", _LOG_LEVELS[event["method"]])
    if event.get("class") == _PREFERENCES_EDITOR:
        method = event.get("method")
        if method in _PREFERENCE_EDITS:
            field("Phase  ", "Edit", " (staged change)")
        elif method == "apply":
            field("Phase  ", "Apply", " (asynchronous disk write)")
        elif method == "commit":
            field("Phase  ", "Commit", " (synchronous)")
    if event.get("class") == _URL and event.get("method") == "openConnection":
        field("Phase  ", "Prepare URLConnection")
        if "destination" in event:
            field("URL    ", display_value(event["destination"]))
    if event.get("class") == _CIPHER and "transformation" in event:
        field("Transformation", display_value(event["transformation"]))
    if "sourcePath" in event:
        field("Path" if event.get("method") == "delete" else "Source", display_value(event["sourcePath"]))
    if "arguments" in event:
        section("ARGUMENTS")
        names = _argument_names(event)
        for i, value in enumerate(event["arguments"]):
            name = names[i] if i < len(names) else i
            if name in ("Bindings", "Options", "DEX buffers") and isinstance(value.get("items"), list):
                items = value["items"]
                count = value["count"]
                field(name, count, f" (showing {len(items)})" if count > len(items) else "")
                for index, item in enumerate(items, 1):
                    typed_value("    ", f"[{index}] ", item, display_value(item))
                continue
            rendered = display_value(value)
            flags = value.get("value")
            if name == "Mode flags" and type(flags) is int:
                rendered = f"0x{flags & 0xffffffff:08X} ({format_uri_grant_flags(flags)})"
            if name == "Context flags" and type(flags) is int:
                labels = " | ".join(label for bit, label in _PACKAGE_CONTEXT_FLAGS.items() if flags & bit)
                rendered = f"0x{flags & 0xffffffff:08X}"
                if labels:
                    rendered += f" ({labels})"
            if name == "Priority" and type(flags) is int and flags in _LOG_PRIORITIES:
                rendered = f"{flags} ({_LOG_PRIORITIES[flags]})"
            if name == "Mode" and event.get("class") == _CIPHER and type(flags) is int and flags in _CIPHER_MODES:
                rendered = f"{flags} ({_CIPHER_MODES[flags]})"
            if event.get("class") == _WEB_SETTINGS and event.get("method") == "setMixedContentMode" and type(flags) is int:
                rendered = _MIXED_CONTENT_MODES.get(flags, rendered)
            typed_value("  ", f"{name} ", value, rendered)
        if names == ("Path",):
            field("Mode", "READ")
        elif names == ("Path", "Append"):
            field("Mode", "WRITE")
            if len(event["types"]) == 1:
                field("Append", "false", " (default)")
        elif names == ("URI", "Mode") and event.get("types") == [_URI]:
            field("Mode", "w", " (default)")
        if not event["arguments"]:
            text.append("\n  No arguments", "dim")
    if isinstance(settings := event.get("webViewSettings"), dict):
        section("WEBVIEW SETTINGS OBSERVED")
        for method, label in _WEB_SETTING_LABELS.items():
            value = settings.get(method)
            if method == "setMixedContentMode" and type(value) is int:
                field(label, _MIXED_CONTENT_MODES.get(value, value))
            elif type(value) is bool:
                field(label, str(value).lower())
        if not settings:
            text.append("\n  No settings observed for this WebView.", "dim")
    if isinstance(command := event.get("processCommand"), dict):
        section("COMMAND")
        items = command.get("items")
        if isinstance(items, list):
            count = command["count"]
            field("Argument vector", count, f" (showing {len(items)})" if count > len(items) else "")
            for index, item in enumerate(items):
                typed_value("    ", f"[{index}] ", item, display_value(item))
        else:
            name = "Command string" if command.get("type") == _STRING else "Argument vector"
            typed_value("  ", f"{name} ", command, display_value(command))
        directory = event.get("workingDirectory")
        if isinstance(directory, dict):
            rendered = "inherited" if "value" in directory and directory["value"] is None else display_value(directory)
            field("Working directory", rendered)
    if "result" in event:
        section("RETURN")
        result = event["result"]
        label = ""
        if event.get("class") == _RESOLVER:
            label = {"insert": "Inserted URI ", "update": "Rows affected ", "delete": "Rows affected "}.get(
                event.get("method"), ""
            )
        typed_value("  ", label, result, display_value(result))
    if "exception" in event:
        section("EXCEPTION")
        text.append(f"\n  {event['exception'].get('type', 'unknown')}")
        text.append(" (original exception propagated)", "dim")
    if "stack" in event:
        section("STACK")
        stack = event["stack"]
        for frame in stack if isinstance(stack, list) else ["unavailable"]:
            text.append(f"\n  {frame}", "dim")
    return text
