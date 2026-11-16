import json
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class ExportResult:
    filename: str
    item_count: int


def history_entries_label(count: int, filtered: bool = False) -> str:
    prefix = "filtered " if filtered else ""
    noun = "entry" if count == 1 else "entries"
    return prefix + noun


def timestamped_filename(prefix: str, extension: str, now: datetime | None = None) -> str:
    timestamp = (now or datetime.now()).strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{timestamp}.{extension}"


def write_history_export(entries: list[dict], now: datetime | None = None) -> ExportResult:
    filename = timestamped_filename("history", "json", now)
    with open(filename, "w") as f:
        json.dump(entries, f, indent=2, default=str)
    return ExportResult(filename, len(entries))


def filter_rule_lines(ignore_list: list[dict], focus_list: list[dict]) -> list[str]:
    lines = []
    for rule in ignore_list:
        lines.append("ignore " + _format_rule(rule))
    for rule in focus_list:
        lines.append("focus " + _format_rule(rule))
    return lines


def write_filter_export(
    ignore_list: list[dict],
    focus_list: list[dict],
    file_label: str,
    now: datetime | None = None,
) -> ExportResult:
    lines = filter_rule_lines(ignore_list, focus_list)
    filename = timestamped_filename(file_label, "txt", now)
    with open(filename, "w") as f:
        f.write("\n".join(lines) + "\n")
    return ExportResult(filename, len(lines))


def _format_rule(rule: dict) -> str:
    return " ".join(f"{key}={value}" for key, value in rule.items())
