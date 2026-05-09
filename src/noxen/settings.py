import os
import sys
from pathlib import Path


APP_NAME = "noxen"
SETTINGS_FILENAME = "settings.txt"

DEFAULT_SETTINGS = {
    "stack": False,
    "stack_depth": 15,
    "intercept": True,
    "intercept_command_bar": True,
    "history_command_bar": True,
}


def _parse_on_off(value: str) -> bool | None:
    if value == "on":
        return True
    if value == "off":
        return False
    return None


def _parse_positive_int(value: str) -> int | None:
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed > 0 else None


def user_config_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("APPDATA")
        if base:
            return Path(base) / APP_NAME
        return Path.home() / "AppData" / "Roaming" / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP_NAME


def settings_file_path() -> Path:
    return user_config_dir() / SETTINGS_FILENAME


def load_settings(path: str | Path | None = None) -> dict:
    path = Path(path) if path is not None else settings_file_path()
    settings = dict(DEFAULT_SETTINGS)
    if not path.exists():
        return settings
    try:
        with path.open() as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip().lower()
                if key == "stack":
                    parsed = _parse_on_off(value)
                    if parsed is not None:
                        settings["stack"] = parsed
                elif key == "stack_depth":
                    parsed = _parse_positive_int(value)
                    if parsed is not None:
                        settings["stack_depth"] = parsed
                elif key == "intercept":
                    parsed = _parse_on_off(value)
                    if parsed is not None:
                        settings["intercept"] = parsed
                elif key == "intercept_command_bar":
                    parsed = _parse_on_off(value)
                    if parsed is not None:
                        settings["intercept_command_bar"] = parsed
                elif key == "history_command_bar":
                    parsed = _parse_on_off(value)
                    if parsed is not None:
                        settings["history_command_bar"] = parsed
    except OSError:
        pass
    return settings


def save_settings(settings: dict, path: str | Path | None = None):
    path = Path(path) if path is not None else settings_file_path()
    settings = {**DEFAULT_SETTINGS, **settings}
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Noxen startup settings",
        f"stack={'on' if settings['stack'] else 'off'}",
        f"stack_depth={settings['stack_depth']}",
        f"intercept={'on' if settings['intercept'] else 'off'}",
        f"intercept_command_bar={'on' if settings['intercept_command_bar'] else 'off'}",
        f"history_command_bar={'on' if settings['history_command_bar'] else 'off'}",
    ]
    with path.open("w") as f:
        f.write("\n".join(lines) + "\n")
