RESIZABLE_HISTORY_COLUMN_KEYS = ("time", "capture_order", "method", "class", "component", "action")
HISTORY_COLUMN_MIN_WIDTH = 5
HISTORY_COLUMN_MAX_WIDTH = 150


def parse_history_column_width(raw_value: str) -> tuple[int | None, str]:
    value_text = raw_value.strip()
    if not value_text or value_text.lower() == "auto":
        return None, ""

    try:
        value = int(value_text)
    except ValueError:
        return None, "Width must be a number or auto"

    if not HISTORY_COLUMN_MIN_WIDTH <= value <= HISTORY_COLUMN_MAX_WIDTH:
        return None, (
            "Width must be auto or between "
            f"{HISTORY_COLUMN_MIN_WIDTH} and {HISTORY_COLUMN_MAX_WIDTH}"
        )

    return value, ""


def normalize_history_column_widths(widths) -> dict[str, int]:
    return normalize_column_widths(widths, RESIZABLE_HISTORY_COLUMN_KEYS)


def normalize_column_widths(widths, allowed_keys) -> dict[str, int]:
    if not isinstance(widths, dict):
        return {}

    normalized = {}
    for key, value in widths.items():
        if key not in allowed_keys:
            continue
        width, error = parse_history_column_width(str(value))
        if error or width is None:
            continue
        normalized[key] = width
    return normalized
