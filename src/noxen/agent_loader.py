import json
from dataclasses import dataclass
from pathlib import Path

from noxen.logging_ui import log_debug, log_error, log_warning


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


@dataclass(frozen=True)
class ScriptLoadResult:
    code: str
    messages: list[str]


def load_json_hooks(filepath: str | Path) -> list:
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def _resolve_runtime_path(configured_path: str | Path, source_default: Path, packaged_default: Path) -> Path:
    path = Path(configured_path)
    if path.exists() or path != source_default:
        return path
    return packaged_default


def load_hook_config(custom_hooks: str | None = None) -> HooksLoadResult:
    hooks = []
    messages = []

    try:
        hooks = load_json_hooks(_resolve_runtime_path(
            DEFAULT_HOOKS_FILE,
            SOURCE_DEFAULT_HOOKS_FILE,
            PACKAGED_DEFAULT_HOOKS_FILE,
        ))
    except FileNotFoundError:
        messages.append(log_error(f"Hooks file not found: {DEFAULT_HOOKS_LABEL}", "loader"))
    except json.JSONDecodeError as e:
        messages.append(log_error(f"Invalid JSON in {DEFAULT_HOOKS_LABEL}: {e}", "loader"))

    if custom_hooks:
        try:
            hooks.extend(load_json_hooks(custom_hooks))
        except FileNotFoundError:
            messages.append(log_error(f"Custom hooks file not found: {custom_hooks}", "loader"))
        except json.JSONDecodeError as e:
            messages.append(log_error(f"Invalid JSON in {custom_hooks}: {e}", "loader"))

    return HooksLoadResult(hooks, messages)


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
