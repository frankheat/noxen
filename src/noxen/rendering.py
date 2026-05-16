from datetime import datetime, timezone

from rich.markup import escape
from rich.text import Text


PENDING_INTENT_FLAGS = [
    (0x40000000, "FLAG_ONE_SHOT"),
    (0x20000000, "FLAG_NO_CREATE"),
    (0x10000000, "FLAG_CANCEL_CURRENT"),
    (0x08000000, "FLAG_UPDATE_CURRENT"),
    (0x04000000, "FLAG_IMMUTABLE"),
    (0x02000000, "FLAG_MUTABLE"),
    (0x01000000, "FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT"),
]

# Values from AOSP android.content.Intent.java. Some bits intentionally have
# multiple names because Android reuses them for activity, broadcast, or hidden
# framework contexts.
INTENT_FLAGS = [
    (0x00000001, ["FLAG_GRANT_READ_URI_PERMISSION"]),
    (0x00000002, ["FLAG_GRANT_WRITE_URI_PERMISSION"]),
    (0x00000004, ["FLAG_FROM_BACKGROUND"]),
    (0x00000008, ["FLAG_DEBUG_LOG_RESOLUTION"]),
    (0x00000010, ["FLAG_EXCLUDE_STOPPED_PACKAGES"]),
    (0x00000020, ["FLAG_INCLUDE_STOPPED_PACKAGES"]),
    (0x00000040, ["FLAG_GRANT_PERSISTABLE_URI_PERMISSION"]),
    (0x00000080, ["FLAG_GRANT_PREFIX_URI_PERMISSION"]),
    (0x00000100, ["FLAG_DIRECT_BOOT_AUTO", "FLAG_DEBUG_TRIAGED_MISSING"]),
    (0x00000200, ["FLAG_ACTIVITY_REQUIRE_DEFAULT"]),
    (0x00000400, ["FLAG_ACTIVITY_REQUIRE_NON_BROWSER"]),
    (0x00000800, ["FLAG_ACTIVITY_MATCH_EXTERNAL", "FLAG_RECEIVER_OFFLOAD_FOREGROUND"]),
    (0x00001000, ["FLAG_ACTIVITY_LAUNCH_ADJACENT"]),
    (0x00002000, ["FLAG_ACTIVITY_RETAIN_IN_RECENTS"]),
    (0x00004000, ["FLAG_ACTIVITY_TASK_ON_HOME"]),
    (0x00008000, ["FLAG_ACTIVITY_CLEAR_TASK"]),
    (0x00010000, ["FLAG_ACTIVITY_NO_ANIMATION"]),
    (0x00020000, ["FLAG_ACTIVITY_REORDER_TO_FRONT"]),
    (0x00040000, ["FLAG_ACTIVITY_NO_USER_ACTION"]),
    (0x00080000, ["FLAG_ACTIVITY_CLEAR_WHEN_TASK_RESET", "FLAG_ACTIVITY_NEW_DOCUMENT"]),
    (0x00100000, ["FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY"]),
    (0x00200000, ["FLAG_ACTIVITY_RESET_TASK_IF_NEEDED", "FLAG_RECEIVER_VISIBLE_TO_INSTANT_APPS"]),
    (0x00400000, ["FLAG_ACTIVITY_BROUGHT_TO_FRONT", "FLAG_RECEIVER_FROM_SHELL"]),
    (0x00800000, ["FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS", "FLAG_RECEIVER_EXCLUDE_BACKGROUND"]),
    (0x01000000, ["FLAG_ACTIVITY_PREVIOUS_IS_TOP", "FLAG_RECEIVER_INCLUDE_BACKGROUND"]),
    (0x02000000, ["FLAG_ACTIVITY_FORWARD_RESULT", "FLAG_RECEIVER_BOOT_UPGRADE"]),
    (0x04000000, ["FLAG_ACTIVITY_CLEAR_TOP", "FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT"]),
    (0x08000000, ["FLAG_ACTIVITY_MULTIPLE_TASK", "FLAG_RECEIVER_NO_ABORT"]),
    (0x10000000, ["FLAG_ACTIVITY_NEW_TASK", "FLAG_RECEIVER_FOREGROUND"]),
    (0x20000000, ["FLAG_ACTIVITY_SINGLE_TOP", "FLAG_RECEIVER_REPLACE_PENDING"]),
    (0x40000000, ["FLAG_ACTIVITY_NO_HISTORY", "FLAG_RECEIVER_REGISTERED_ONLY"]),
    (0x80000000, ["FLAG_IGNORE_EPHEMERAL", "FLAG_RECEIVER_OFFLOAD"]),
]

HISTORY_OUTCOME_CELL = {
    "forwarded":          Text("→",  style="bold #26a368"),
    "modified_forwarded": Text("✎→", style="bold #26a368"),
    "dropped":            Text("✗",  style="bold red"),
}


def decode_pending_intent_flags(raw_flags):
    if raw_flags is None:
        return None
    return [name for mask, name in PENDING_INTENT_FLAGS if raw_flags & mask]


def decode_intent_flags(raw_flags):
    flags = _parse_flag_int(raw_flags)
    if flags is None:
        return None

    normalized_flags = flags & 0xFFFFFFFF
    decoded = []
    known_mask = 0
    for mask, names in INTENT_FLAGS:
        known_mask |= mask
        if normalized_flags & mask:
            decoded.append(" / ".join(names))

    unknown_bits = normalized_flags & ~known_mask
    if unknown_bits:
        decoded.append(f"UNKNOWN_BITS(0x{unknown_bits:08X})")
    return decoded


def entry_to_filter_context(entry: dict) -> dict:
    info = entry.get("intent", {}) or {}
    return {
        "class": str(entry.get("class") or ""),
        "method": str(entry.get("method") or ""),
        "action": str(info.get("action") or ""),
        "component": str(info.get("component") or ""),
        "data": str(info.get("data") or ""),
        "flags": str(info.get("flags") or "0"),
        "category": info.get("categories", []),
    }


def payload_to_filter_context(payload: dict) -> dict:
    info = payload.get("infoIntent", {}) or {}
    return {
        "class": str(payload.get("className", "")),
        "method": str(payload.get("methodName", "")),
        "action": str(info.get("action") or ""),
        "component": str(info.get("component") or ""),
        "data": str(info.get("data") or ""),
        "flags": str(info.get("flags") or "0"),
        "category": info.get("categories", []),
    }


def payload_to_history_entry(payload: dict, now: datetime | None = None) -> dict:
    timestamp = (now or datetime.now(timezone.utc)).isoformat()
    return {
        "id": None,
        "timestamp": timestamp,
        "class": payload.get("className"),
        "method": payload.get("methodName"),
        "intent": payload.get("infoIntent") or {},
        "stackTrace": payload.get("stackTrace") or [],
        "pendingIntentFlags": payload.get("pendingIntentFlags"),
        "attackSurface": payload.get("attackSurface") or {},
    }


def history_sort_key(entry: dict, column: str | None):
    info = entry.get("intent", {}) or {}
    if column == "id":
        return entry.get("id", 0)
    if column == "time":
        return entry.get("timestamp", "")
    if column == "method":
        return (entry.get("method") or "").lower()
    if column == "class":
        return (entry.get("class") or "").lower()
    if column == "component":
        return (info.get("component") or "").lower()
    if column == "action":
        return (info.get("action") or "").lower()
    if column == "extras":
        return bool(info.get("extras"))
    if column == "outcome":
        return entry.get("outcome") or ""
    return ""


def history_search_matches(entry: dict, query: str) -> bool:
    normalized_query = query.lower()
    info = entry.get("intent", {}) or {}
    fields = [
        str(entry.get("class") or ""),
        str(entry.get("method") or ""),
        str(info.get("action") or ""),
        str(info.get("component") or ""),
        str(info.get("data") or ""),
        str(info.get("flags") or ""),
    ]
    for category in info.get("categories", []):
        fields.append(str(category))
    for key, value in (info.get("extras") or {}).items():
        fields.append(str(key))
        fields.append(str(value.get("value", "")))
    return any(normalized_query in field.lower() for field in fields)


def filter_sort_history_entries(
    entries: list[dict],
    filter_manager,
    search_text: str = "",
    sort_column: str | None = None,
    sort_reverse: bool = False,
) -> list[dict]:
    filtered = []
    for entry in list(entries):
        if not filter_manager.is_visible(entry_to_filter_context(entry)):
            continue
        filtered.append(entry)

    if search_text:
        filtered = [entry for entry in filtered if history_search_matches(entry, search_text)]
    if sort_column:
        filtered.sort(key=lambda entry: history_sort_key(entry, sort_column), reverse=sort_reverse)
    return filtered


def history_row_values(entry: dict, visible_columns: set[str], columns: list[tuple[str, str]]) -> list:
    info = entry.get("intent", {}) or {}
    extras = info.get("extras", {}) or {}
    timestamp = entry.get("timestamp", "")
    time_str = timestamp[:19].replace("T", " ") if len(timestamp) >= 19 else timestamp
    outcome = entry.get("outcome")
    all_values = {
        "id":        str(entry["id"]),
        "outcome":   HISTORY_OUTCOME_CELL.get(outcome, Text("")),
        "time":      time_str,
        "method":    str(entry.get("method") or ""),
        "class":     str(entry.get("class") or ""),
        "component": str(info.get("component") or ""),
        "action":    str(info.get("action") or ""),
        "extras":    Text("✓", style="#26a368") if extras else "",
    }
    return [all_values[key] for key, _label in columns if key in visible_columns]


def _render_caller_surface_label(attack_surface: dict) -> str | None:
    caller_exported = attack_surface.get("callerExported")
    if caller_exported is True:
        return "[#C94A8A][Exported][/#C94A8A]"
    if caller_exported is False:
        return "[#26a368][Not exported][/#26a368]"
    return None


def _render_intent_surface_label(attack_surface: dict) -> str | None:
    intent_explicit = attack_surface.get("intentExplicit")
    if intent_explicit is False:
        return "[#C94A8A][Implicit][/#C94A8A]"
    if intent_explicit is True:
        return "[#26a368][Explicit][/#26a368]"
    return None


def _pending_intent_flag_color(flags: list[str]) -> str:
    if "FLAG_MUTABLE" in flags:
        return "#FFB1B1"
    if "FLAG_IMMUTABLE" in flags:
        return "#26a368"
    return "#F2C94C"


def _markup(value) -> str:
    return "" if value is None else escape(str(value))


def _parse_flag_int(raw_flags):
    if raw_flags is None or raw_flags == "":
        return None
    try:
        if isinstance(raw_flags, str):
            return int(raw_flags.strip(), 0)
        return int(raw_flags)
    except (TypeError, ValueError):
        return None


def _format_intent_flags(raw_flags) -> str:
    flags = _parse_flag_int(raw_flags)
    if flags is None:
        return _markup(raw_flags)

    normalized_flags = flags & 0xFFFFFFFF
    decoded = decode_intent_flags(flags)
    hex_value = f"0x{normalized_flags:08X}"
    if not decoded:
        return hex_value
    return f"{hex_value}  [#F2C94C]{_markup(' | '.join(decoded))}[/#F2C94C]"


def render_intercept_block(payload: dict, intercept_counter: int, show_stack: bool, stack_depth: int) -> str:
    info = payload.get("infoIntent", {}) or {}
    context = {
        "class": _markup(payload.get("className")),
        "method": _markup(payload.get("methodName")),
        "action": _markup(info.get("action")),
        "component": _markup(info.get("component")),
        "data": _markup(info.get("data")),
    }

    out = []
    out.append("[bold #F2C94C]" + "━" * 50 + "[/bold #F2C94C]")
    out.append(f"[bold #F2C94C]  INTERCEPTED[/bold #F2C94C] [#F2C94C]#{intercept_counter}[/#F2C94C]")

    pi_flags = decode_pending_intent_flags(payload.get("pendingIntentFlags"))

    attack_surface = payload.get("attackSurface") or {}
    caller_label = _render_caller_surface_label(attack_surface)
    intent_label = _render_intent_surface_label(attack_surface)
    out.append(f"[bold]Method:[/bold]    {context['method']}")
    class_label = f"  {caller_label}" if caller_label else ""
    out.append(f"[bold]Class:[/bold]     {context['class']}{class_label}")

    if pi_flags is not None:
        flags_str = " | ".join(pi_flags) if pi_flags else "(none)"
        color = _pending_intent_flag_color(pi_flags)
        out.append(f"[bold]PI Flags:[/bold]  [{color}]{flags_str}[/{color}]")

    if intent_label:
        out.append(f"[bold]Intent:[/bold]    {intent_label}")
    if context["component"]:
        out.append(f"[bold]Component:[/bold] [secondary]{context['component']}[/secondary]")
    if context["action"]:
        out.append(f"[bold]Action:[/bold]    {context['action']}")
    if context["data"]:
        out.append(f"[bold]Data:[/bold]      {context['data']}")
    if info.get("flags"):
        out.append(f"[bold]Flags:[/bold]     {_format_intent_flags(info.get('flags'))}")

    if info.get("categories"):
        out.append(f"[bold]Categories:[/bold] {', '.join(_markup(category) for category in info['categories'])}")

    if info.get("extras"):
        out.append("[bold]Extras:[/bold]")
        for key, value in info["extras"].items():
            out.append(f"  - {_markup(key)} ({_markup(value.get('type'))}): {_markup(value.get('value'))}")

    if show_stack:
        trace = payload.get("stackTrace", [])
        if trace:
            out.append("\n[bold]Stack Trace:[/bold]")
            for line in trace[:stack_depth]:
                out.append(f"  {_markup(line)}")
            if len(trace) > stack_depth:
                out.append(f"  ... (+{len(trace)-stack_depth} more)")

    out.append("")
    return "\n".join(out)


def render_intent_detail(entry: dict, show_stack: bool = False, stack_depth: int = 15) -> str:
    info = entry.get("intent", {}) or {}
    pi_flags = decode_pending_intent_flags(entry.get("pendingIntentFlags"))

    outcome = entry.get("outcome")
    outcome_str = {
        "forwarded":          "[#26a368]→ forwarded[/#26a368]",
        "modified_forwarded": "[#26a368]✎→ forwarded (modified)[/#26a368]",
        "dropped":            "[#FFB1B1]✗ dropped[/#FFB1B1]",
    }.get(outcome or "", "[dim]pending[/dim]")

    timestamp = entry.get("timestamp", "")
    time_str = timestamp[:19].replace("T", " ") if len(timestamp) >= 19 else timestamp

    sep = "[dim]─[/dim]" * 50

    out = []
    out.append("")
    out.append(
        f"[bold #F2C94C]#{entry['id']}[/bold #F2C94C]"
        f"  [dim]{time_str}[/dim]"
        f"  {outcome_str}"
    )
    out.append(sep)

    attack_surface = entry.get("attackSurface") or {}
    caller_label = _render_caller_surface_label(attack_surface)
    intent_label = _render_intent_surface_label(attack_surface)

    out.append(f"  [bold]Method[/bold]     {_markup(entry.get('method'))}")
    class_label = f"  {caller_label}" if caller_label else ""
    out.append(f"  [bold]Class[/bold]      [dim]{_markup(entry.get('class'))}[/dim]{class_label}")

    has_intent = (
        any(info.get(key) for key in ("action", "component", "data", "flags", "categories")) or
        intent_label is not None
    )
    if has_intent:
        out.append("")
        intent_title = f"  [bold dim]INTENT[/bold dim]  {intent_label}" if intent_label else "  [bold dim]INTENT[/bold dim]"
        out.append(intent_title)
        if info.get("action"):
            out.append(f"  [bold]Action[/bold]     {_markup(info.get('action'))}")
        if info.get("component"):
            out.append(f"  [bold]Component[/bold]  {_markup(info.get('component'))}")
        if info.get("data"):
            out.append(f"  [bold]Data[/bold]       {_markup(info.get('data'))}")
        if info.get("flags"):
            out.append(f"  [bold]Flags[/bold]      {_format_intent_flags(info.get('flags'))}")
        if info.get("categories"):
            for category in info["categories"]:
                out.append(f"  [bold]Category[/bold]   {_markup(category)}")

    if pi_flags is not None:
        out.append("")
        out.append("  [bold dim]PENDING INTENT[/bold dim]")
        flags_str = " | ".join(pi_flags) if pi_flags else "(none)"
        color = _pending_intent_flag_color(pi_flags)
        out.append(f"  [bold]Flags[/bold]      [{color}]{flags_str}[/{color}]")

    if info.get("extras"):
        out.append("")
        out.append("  [bold dim]EXTRAS[/bold dim]")
        for key, value in info["extras"].items():
            out.append(
                f"  [bold]{_markup(key)}[/bold]  "
                f"[dim]({_markup(value.get('type'))})[/dim]  {_markup(value.get('value'))}"
            )

    original = entry.get("original_intent")
    if original:
        out.append("")
        out.append("  [bold dim]CHANGES[/bold dim]")
        out.append(sep)
        has_changes = False

        orig_action = original.get("action") or ""
        mod_action = info.get("action") or ""
        if orig_action != mod_action:
            has_changes = True
            out.append(
                f"  [bold]Action[/bold]     "
                f"[dim]{_markup(orig_action or '(none)')}[/dim] → {_markup(mod_action or '(none)')}"
            )

        orig_data = original.get("data") or ""
        mod_data = info.get("data") or ""
        if orig_data != mod_data:
            has_changes = True
            out.append(
                f"  [bold]Data[/bold]       "
                f"[dim]{_markup(orig_data or '(none)')}[/dim] → {_markup(mod_data or '(none)')}"
            )

        orig_categories = list(original.get("categories") or [])
        mod_categories = list(info.get("categories") or [])
        removed_categories = [category for category in orig_categories if category not in mod_categories]
        added_categories = [category for category in mod_categories if category not in orig_categories]
        if removed_categories or added_categories:
            has_changes = True
            out.append("")
            out.append("  [bold dim]CATEGORIES[/bold dim]")
            for category in removed_categories:
                out.append(f"  [#FFB1B1][-][/#FFB1B1]  [dim]{_markup(category)}[/dim]")
            for category in added_categories:
                out.append(f"  [#26a368][+][/#26a368]  {_markup(category)}")

        orig_extras = original.get("extras") or {}
        mod_extras = info.get("extras") or {}
        removed_keys = [key for key in orig_extras if key not in mod_extras]
        added_keys = [key for key in mod_extras if key not in orig_extras]
        changed_keys = [
            key for key in orig_extras
            if key in mod_extras and
            str(orig_extras[key].get("value", "")) != str(mod_extras[key].get("value", ""))
        ]
        if removed_keys or added_keys or changed_keys:
            has_changes = True
            out.append("")
            out.append("  [bold dim]EXTRAS[/bold dim]")
            for key in changed_keys:
                old_value = orig_extras[key]
                new_value = mod_extras[key]
                out.append(
                    f"  [#F2C94C][~][/#F2C94C] [bold]{_markup(key)}[/bold]  "
                    f"[dim]({_markup(old_value.get('type'))})[/dim]  "
                    f"[dim]{_markup(old_value.get('value'))}[/dim] → {_markup(new_value.get('value'))}"
                )
            for key in removed_keys:
                value = orig_extras[key]
                out.append(
                    f"  [#FFB1B1][-][/#FFB1B1] [bold]{_markup(key)}[/bold]  "
                    f"[dim]({_markup(value.get('type'))})[/dim]  [dim]{_markup(value.get('value'))}[/dim]"
                )
            for key in added_keys:
                value = mod_extras[key]
                out.append(
                    f"  [#26a368][+][/#26a368] [bold]{_markup(key)}[/bold]  "
                    f"[dim]({_markup(value.get('type'))})[/dim]  {_markup(value.get('value'))}"
                )

        if not has_changes:
            out.append("  [dim](forwarded without changes)[/dim]")

    trace = entry.get("stackTrace", [])
    if show_stack:
        out.append("")
        if trace:
            out.append("  [bold dim]STACK TRACE[/bold dim]")
            for line in trace[:stack_depth]:
                out.append(f"  [dim]{_markup(line)}[/dim]")
            if len(trace) > stack_depth:
                out.append(f"  [dim]... (+{len(trace)-stack_depth} more)[/dim]")
        else:
            out.append("  [dim]No stack trace captured.[/dim]")

    out.append("")
    return "\n".join(out)
