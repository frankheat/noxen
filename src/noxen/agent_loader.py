import json
from dataclasses import dataclass
from pathlib import Path

from noxen.logging_ui import log_debug, log_warning


PACKAGE_ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = PACKAGE_ROOT.parents[1]
RUNTIME_ROOT = PACKAGE_ROOT / "runtime"

SOURCE_DEFAULT_HOOKS_FILE = SOURCE_ROOT / "config" / "hooks.json"
SOURCE_BUNDLE_SCRIPT_FILE = SOURCE_ROOT / "agent" / "script_bundle.js"
SOURCE_SCRIPT_FILE_DEFAULT = SOURCE_ROOT / "agent" / "script.js"
SOURCE_SYSTEM_SERVER_BUNDLE_SCRIPT_FILE = SOURCE_ROOT / "agent" / "system_server_bundle.js"
SOURCE_SYSTEM_SERVER_SCRIPT_FILE = SOURCE_ROOT / "agent" / "system_server.js"

PACKAGED_DEFAULT_HOOKS_FILE = RUNTIME_ROOT / "config" / "hooks.json"
PACKAGED_BUNDLE_SCRIPT_FILE = RUNTIME_ROOT / "agent" / "script_bundle.js"
PACKAGED_SOURCE_SCRIPT_FILE = RUNTIME_ROOT / "agent" / "script.js"
PACKAGED_SYSTEM_SERVER_BUNDLE_SCRIPT_FILE = RUNTIME_ROOT / "agent" / "system_server_bundle.js"
PACKAGED_SYSTEM_SERVER_SOURCE_SCRIPT_FILE = RUNTIME_ROOT / "agent" / "system_server.js"

DEFAULT_HOOKS_FILE = SOURCE_DEFAULT_HOOKS_FILE
BUNDLE_SCRIPT_FILE = SOURCE_BUNDLE_SCRIPT_FILE
SOURCE_SCRIPT_FILE = SOURCE_SCRIPT_FILE_DEFAULT
SYSTEM_SERVER_BUNDLE_SCRIPT_FILE = SOURCE_SYSTEM_SERVER_BUNDLE_SCRIPT_FILE
SYSTEM_SERVER_SOURCE_SCRIPT_FILE = SOURCE_SYSTEM_SERVER_SCRIPT_FILE
DEFAULT_HOOKS_LABEL = "config/hooks.json"
BUNDLE_SCRIPT_LABEL = "agent/script_bundle.js"
SOURCE_SCRIPT_LABEL = "agent/script.js"
SYSTEM_SERVER_BUNDLE_SCRIPT_LABEL = "agent/system_server_bundle.js"
SYSTEM_SERVER_SOURCE_SCRIPT_LABEL = "agent/system_server.js"
PASSTHROUGH_AGENT = (
    "rpc.exports = { proxy: function(h){}, forward: function(){}, drop: function(){}, "
    "interceptoff: function(){}, intercepton: function(){} };"
)
PASSTHROUGH_SYSTEM_SERVER_AGENT = (
    "rpc.exports = { init: function(c){}, holdstart: function(h){}, "
    "holdend: function(i,p){}, clear: function(){}, status: function(){return {};}};"
)


@dataclass(frozen=True)
class HooksLoadResult:
    hooks: list
    messages: list[str]
    sources: tuple[str, ...] = ()
    custom_count: int = 0


class HookConfigError(ValueError):
    """A hook configuration could not be read or is structurally invalid."""

    def __init__(self, label: str, details: list[str]):
        self.label = label
        self.details = tuple(details)
        summary = details[0] if details else "invalid hook configuration"
        if len(details) > 1:
            summary += f" (+{len(details) - 1} more)"
        super().__init__(f"{label}: {summary}")


@dataclass(frozen=True)
class ScriptLoadResult:
    code: str
    messages: list[str]


def load_json_hooks(filepath: str | Path) -> list:
    with open(filepath, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def validate_hook_config(data, label: str = "hook config") -> tuple[list[dict], list[str]]:
    """Validate and normalize the JSON shape understood by the app agent."""
    if not isinstance(data, list):
        raise HookConfigError(label, ["top-level value must be a JSON array"])

    hooks = []
    errors = []
    warnings = []
    allowed_fields = {"clazz", "method", "args", "minApi"}

    for index, raw in enumerate(data):
        prefix = f"hook[{index}]"
        if not isinstance(raw, dict):
            errors.append(f"{prefix} must be an object")
            continue

        unknown = sorted(set(raw) - allowed_fields)
        if unknown:
            warnings.append(f"{prefix}: ignored unknown field(s): {', '.join(unknown)}")

        normalized = {}
        for field in ("clazz", "method"):
            value = raw.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{prefix}.{field} must be a non-empty string")
            else:
                normalized[field] = value.strip()

        args = raw.get("args")
        if not isinstance(args, list):
            errors.append(f"{prefix}.args must be an array of Java type names")
        else:
            normalized_args = []
            for arg_index, arg in enumerate(args):
                if not isinstance(arg, str) or not arg.strip():
                    errors.append(f"{prefix}.args[{arg_index}] must be a non-empty string")
                else:
                    normalized_args.append(arg.strip())
            normalized["args"] = normalized_args

        if "minApi" in raw:
            min_api = raw["minApi"]
            if isinstance(min_api, bool) or not isinstance(min_api, int) or min_api < 1:
                errors.append(f"{prefix}.minApi must be a positive integer")
            else:
                normalized["minApi"] = min_api

        if all(field in normalized for field in ("clazz", "method", "args")):
            method = normalized["method"]
            clazz = normalized["clazz"]
            hook_args = normalized["args"]
            if method == "getIntent":
                if hook_args:
                    errors.append(f"{prefix}: getIntent hooks must have an empty args array")
            elif clazz == "android.app.PendingIntent":
                if (
                    method not in {"getActivity", "getBroadcast", "getService"}
                    or len(hook_args) < 4
                    or hook_args[2] != "android.content.Intent"
                ):
                    errors.append(
                        f"{prefix}: unsupported PendingIntent hook; expected a supported factory "
                        "with android.content.Intent as args[2]"
                    )
            elif "android.content.Intent" not in hook_args:
                errors.append(
                    f"{prefix}: unsupported hook; args must contain android.content.Intent"
                )

        hooks.append(normalized)

    if errors:
        raise HookConfigError(label, errors)
    return hooks, warnings


def _load_validated_hooks(filepath: str | Path, label: str) -> tuple[list[dict], list[str]]:
    try:
        data = load_json_hooks(filepath)
    except FileNotFoundError:
        raise HookConfigError(label, ["file not found"]) from None
    except IsADirectoryError:
        raise HookConfigError(label, ["path is a directory, not a file"]) from None
    except PermissionError:
        raise HookConfigError(label, ["file is not readable"]) from None
    except UnicodeError as error:
        raise HookConfigError(label, [f"file is not valid UTF-8: {error}"]) from None
    except json.JSONDecodeError as error:
        raise HookConfigError(
            label,
            [f"invalid JSON at line {error.lineno}, column {error.colno}: {error.msg}"],
        ) from None
    except OSError as error:
        raise HookConfigError(label, [f"cannot read file: {error}"]) from None
    return validate_hook_config(data, label)


def _resolve_runtime_path(configured_path: str | Path, source_default: Path, packaged_default: Path) -> Path:
    path = Path(configured_path)
    if path.exists() or path != source_default:
        return path
    return packaged_default


def load_hook_config(custom_hooks: str | None = None) -> HooksLoadResult:
    hooks = []
    messages = []
    sources = []
    seen = {}
    custom_count = 0

    default_path = _resolve_runtime_path(
        DEFAULT_HOOKS_FILE,
        SOURCE_DEFAULT_HOOKS_FILE,
        PACKAGED_DEFAULT_HOOKS_FILE,
    )
    default_hooks, default_warnings = _load_validated_hooks(default_path, DEFAULT_HOOKS_LABEL)
    for warning in default_warnings:
        messages.append(log_warning(warning, "loader"))

    inputs = [(default_hooks, "default")]
    if custom_hooks:
        custom_label = f"custom hook config {custom_hooks}"
        custom_data, custom_warnings = _load_validated_hooks(custom_hooks, custom_label)
        for warning in custom_warnings:
            messages.append(log_warning(warning, "loader"))
        inputs.append((custom_data, "custom"))

    for group, origin in inputs:
        for index, hook in enumerate(group):
            signature = (hook["clazz"], hook["method"], tuple(hook["args"]))
            source = f"{origin} hook[{index}]"
            previous = seen.get(signature)
            if previous is not None:
                messages.append(log_warning(
                    f"Duplicate {source} ignored; already defined by {previous}", "loader"
                ))
                continue
            seen[signature] = source
            hooks.append(hook)
            sources.append(source)
            if origin == "custom":
                custom_count += 1

    return HooksLoadResult(hooks, messages, tuple(sources), custom_count)


def load_agent_script(extra_script: str | None = None) -> ScriptLoadResult:
    messages = []
    bundle_file = _resolve_runtime_path(
        BUNDLE_SCRIPT_FILE,
        SOURCE_BUNDLE_SCRIPT_FILE,
        PACKAGED_BUNDLE_SCRIPT_FILE,
    )
    source_file = _resolve_runtime_path(
        SOURCE_SCRIPT_FILE,
        SOURCE_SCRIPT_FILE_DEFAULT,
        PACKAGED_SOURCE_SCRIPT_FILE,
    )
    try:
        with open(bundle_file, "r", encoding="utf-8") as f:
            code = f.read()
    except FileNotFoundError:
        try:
            with open(source_file, "r", encoding="utf-8") as f:
                code = f.read()
            messages.append(
                log_warning(
                    f"{BUNDLE_SCRIPT_LABEL} not found; using {SOURCE_SCRIPT_LABEL} "
                    "(Frida >=17 unsupported)",
                    "loader",
                )
            )
        except FileNotFoundError:
            messages.append(log_warning("No agent script found; running in passthrough mode", "loader"))
            code = PASSTHROUGH_AGENT

    if extra_script:
        try:
            with open(extra_script, "r", encoding="utf-8") as f:
                code += "\n\n" + f.read()
            messages.append(log_debug(f"Extra script loaded: {extra_script}", "loader"))
        except FileNotFoundError:
            messages.append(log_warning(f"Extra script not found: {extra_script}", "loader"))

    return ScriptLoadResult(code, messages)


def load_system_server_script() -> ScriptLoadResult:
    messages = []
    bundle_file = _resolve_runtime_path(
        SYSTEM_SERVER_BUNDLE_SCRIPT_FILE,
        SOURCE_SYSTEM_SERVER_BUNDLE_SCRIPT_FILE,
        PACKAGED_SYSTEM_SERVER_BUNDLE_SCRIPT_FILE,
    )
    source_file = _resolve_runtime_path(
        SYSTEM_SERVER_SOURCE_SCRIPT_FILE,
        SOURCE_SYSTEM_SERVER_SCRIPT_FILE,
        PACKAGED_SYSTEM_SERVER_SOURCE_SCRIPT_FILE,
    )
    try:
        with open(bundle_file, "r", encoding="utf-8") as f:
            code = f.read()
    except FileNotFoundError:
        try:
            with open(source_file, "r", encoding="utf-8") as f:
                code = f.read()
            messages.append(
                log_warning(
                    f"{SYSTEM_SERVER_BUNDLE_SCRIPT_LABEL} not found; using "
                    f"{SYSTEM_SERVER_SOURCE_SCRIPT_LABEL} (Frida >=17 unsupported)",
                    "loader",
                )
            )
        except FileNotFoundError:
            messages.append(log_warning("No system_server agent found; Input ANR bypass disabled", "loader"))
            code = PASSTHROUGH_SYSTEM_SERVER_AGENT
    return ScriptLoadResult(code, messages)
