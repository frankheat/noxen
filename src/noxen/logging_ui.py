from rich.markup import escape


SUCCESS_COLOR = "#26a368"
SOURCE_WIDTH = 13
LEVEL_WIDTH = 5

_LEVELS = {
    "debug": ("DEBUG", "dim"),
    "info": ("INFO", "dim"),
    "success": ("OK", SUCCESS_COLOR),
    "warning": ("WARN", "yellow"),
    "error": ("ERROR", "red"),
}


def format_log(level: str, message: str, source: str | None = None) -> str:
    label, color = _LEVELS.get(level, _LEVELS["info"])
    source_text = escape((source or "")[:SOURCE_WIDTH])
    safe_message = escape(str(message))
    return f"[dim]{source_text:<{SOURCE_WIDTH}}[/dim] [{color}]{label:<{LEVEL_WIDTH}}[/{color}] {safe_message}"


def is_debug_log(text: str) -> bool:
    return f"[dim]{'DEBUG':<{LEVEL_WIDTH}}[/dim]" in text


def log_debug(message: str, source: str | None = None) -> str:
    return format_log("debug", message, source)


def log_info(message: str, source: str | None = None) -> str:
    return format_log("info", message, source)


def log_success(message: str, source: str | None = None) -> str:
    return format_log("success", message, source)


def log_warning(message: str, source: str | None = None) -> str:
    return format_log("warning", message, source)


def log_error(message: str, source: str | None = None) -> str:
    return format_log("error", message, source)
