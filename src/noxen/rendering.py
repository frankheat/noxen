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

def history_outcome_cell(
    outcome: str | None,
    success_color: str = "#26a368",
    error_color: str = "red",
) -> Text:
    if outcome == "forwarded":
        return Text("→", style=f"bold {success_color}")
    if outcome == "modified_forwarded":
        return Text("✎→", style=f"bold {success_color}")
    if outcome == "dropped":
        return Text("✗", style=f"bold {error_color}")
    return Text("")


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


def history_row_values(
    entry: dict,
    visible_columns: set[str],
    columns: list[tuple[str, str]],
    success_color: str = "#26a368",
    error_color: str = "red",
) -> list:
    info = entry.get("intent", {}) or {}
    extras = info.get("extras", {}) or {}
    timestamp = entry.get("timestamp", "")
    time_str = timestamp[:19].replace("T", " ") if len(timestamp) >= 19 else timestamp
    outcome = entry.get("outcome")
    all_values = {
        "id":        str(entry["id"]),
        "outcome":   history_outcome_cell(outcome, success_color, error_color),
        "time":      time_str,
        "method":    str(entry.get("method") or ""),
        "class":     str(entry.get("class") or ""),
        "component": str(info.get("component") or ""),
        "action":    str(info.get("action") or ""),
        "extras":    Text("✓", style=success_color) if extras else "",
    }
    return [all_values[key] for key, _label in columns if key in visible_columns]


_LABEL_WIDTH = 13          # fixed label column so ":" aligns across every event
_CHILD_WIDTH = 19          # tree child column ("Required Permission")
_TREE_INDENT = " " * 18    # tree hangs under the parent's value column

_OUTCOME_LABEL = {
    "forwarded": "FORWARDED",
    "modified_forwarded": "MODIFIED",
    "dropped": "DROPPED",
}


def _section(title: str) -> str:
    """A `[SECTION]` header (brackets escaped so Rich renders them literally)."""
    return f"[bold]\\[{title}][/bold]"


def _row(label: str, value: str) -> str:
    """An aligned `  label : value` row: dim label and colon, value at full brightness."""
    return f"  [dim]{label:<{_LABEL_WIDTH}} :[/dim] {value}"


def _format_permission(perm: dict | None) -> str | None:
    """`name (level)` for a {name, level} permission, or None when absent."""
    if not perm:
        return None
    name = _markup(perm.get("name"))
    if not name:
        return None
    level = perm.get("level")
    return f"{name} ({_markup(level)})" if level else name


def _subject_tree(exported, permission: dict | None) -> list[str]:
    """Tree lines for a component's Exported flag and optional Required Permission.

    The permission line is omitted when the component has none, leaving only Exported.
    """
    children = []
    if exported is not None:
        children.append(("Exported", "true" if exported else "false"))
    formatted = _format_permission(permission)
    if formatted:
        children.append(("Required Permission", formatted))
    lines = []
    for index, (label, value) in enumerate(children):
        branch = "└─" if index == len(children) - 1 else "├─"
        lines.append(f"{_TREE_INDENT}[dim]{branch} {label:<{_CHILD_WIDTH}} :[/dim] {value}")
    return lines


def _simple_type(java_type) -> str:
    """Compact type name for the EXTRAS table: `java.lang.String` -> `String`."""
    if not java_type:
        return "?"
    return str(java_type).rsplit(".", 1)[-1].split("$", 1)[0]


def _format_pending_flags(raw_flags) -> str | None:
    """`0x...  [NAME | NAME]` for PendingIntent flags, or None when not applicable."""
    names = decode_pending_intent_flags(raw_flags)
    if names is None:
        return None
    hex_value = f"0x{int(raw_flags) & 0xFFFFFFFF:08X}"
    if not names:
        return f"{hex_value}  (none)"
    return f"{hex_value}  \\[{_markup(' | '.join(names))}]"


def _target_lines(attack_surface: dict) -> list[str]:
    """The `Target` row (+ its exported/permission tree) for a sending event."""
    component = attack_surface.get("targetComponent")
    if component and attack_surface.get("targetUnreadable"):
        return [_row("Target", f"{_markup(component)} [dim](couldn't read — not visible)[/dim]")]
    if component:
        suffix = " [dim](resolved)[/dim]" if attack_surface.get("targetResolved") else ""
        lines = [_row("Target", f"{_markup(component)}{suffix}")]
        lines += _subject_tree(attack_surface.get("targetExported"), attack_surface.get("targetPermission"))
        return lines
    if attack_surface.get("targetReceiverCount"):
        return [_row("Target", f"(resolved) {attack_surface['targetReceiverCount']} receivers")]
    if attack_surface.get("targetType") == "receiver":
        # PackageManager only knows manifest receivers: runtime-registered ones may still
        # receive the broadcast, so "unresolved" would wrongly suggest that nobody does.
        return [_row("Target", "(no manifest receiver) [dim]— dynamic receivers are not visible[/dim]")]
    return [_row("Target", "(unresolved)")]


def _hook_caller_lines(class_name, method, attack_surface: dict) -> list[str]:
    lines = [_row("Class", _markup(class_name))]
    # Receiving methods: the exposed component is the caller, so its tree hangs here.
    if "callerExported" in attack_surface:
        lines += _subject_tree(attack_surface.get("callerExported"), attack_surface.get("callerPermission"))
    lines.append(_row("Method", f"{_markup(method)}()"))
    return lines


def _intent_type(info: dict, attack_surface: dict) -> str:
    """EXPLICIT, or IMPLICIT qualified by who can receive it.

    An implicit intent limited with setPackage() reaches only that app; without it, any
    app with a matching filter. Captures made before noxen recorded the package have no
    `package` key, so they stay unqualified rather than guessed.
    """
    if attack_surface.get("intentExplicit"):
        return "EXPLICIT"
    if "package" not in info:
        return "IMPLICIT"
    if info.get("package"):
        return "IMPLICIT [dim](package-scoped)[/dim]"
    return "IMPLICIT [dim](any app)[/dim]"


def _payload_lines(info: dict, attack_surface: dict) -> list[str]:
    lines = []
    # Type + Target only apply to sending methods.
    if "intentExplicit" in attack_surface:
        lines.append(_row("Type", _intent_type(info, attack_surface)))
        lines += _target_lines(attack_surface)
        enforced = _format_permission(attack_surface.get("broadcastPermission"))
        if enforced:
            lines.append(_row("Enforced Perm", enforced))
    lines.append(_row("Action", _markup(info.get("action")) if info.get("action") else "None"))
    lines.append(_row("Data (URI)", _markup(info.get("data")) if info.get("data") else "None"))
    if info.get("package"):
        lines.append(_row("Package", _markup(info.get("package"))))
    lines.append(_row("Flags", _format_intent_flags(info.get("flags") or 0)))
    for category in info.get("categories") or []:
        lines.append(_row("Category", _markup(category)))
    return lines


_EXTRA_RENDER_MAX_DEPTH = 12
_EXTRA_RENDER_MAX_LINES = 400
_EXTRA_RENDER_MAX_TEXT = 2048

_ARRAY_DISPLAY_TYPES = {
    "[Z": "boolean[]",
    "[B": "byte[]",
    "[C": "char[]",
    "[S": "short[]",
    "[I": "int[]",
    "[J": "long[]",
    "[F": "float[]",
    "[D": "double[]",
    "[Ljava.lang.String;": "String[]",
}


def _extra_display_text(value) -> str:
    """Single-line, bounded text so an extra cannot break or flood the layout."""
    if value is None:
        return "None"
    text = str(value).replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    if len(text) > _EXTRA_RENDER_MAX_TEXT:
        text = text[:_EXTRA_RENDER_MAX_TEXT] + "…"
    return _markup(text)


def _extra_type_name(node: dict) -> str:
    display = node.get("displayType") or node.get("noxenType")
    if display:
        return str(display)
    java_type = node.get("type")
    return _ARRAY_DISPLAY_TYPES.get(str(java_type), _simple_type(java_type))


def _extra_type_markup(type_name: str) -> str:
    return f"[dim]\\[{_markup(type_name)}][/dim]"


def _extra_tree_prefix(prefix: str, is_last: bool) -> str:
    return f"[dim]{_markup(prefix + ('└─ ' if is_last else '├─ '))}[/dim]"


def _legacy_extra_node(extra: dict) -> dict:
    """Adapt captures made before structured extras to the tree renderer."""
    return {
        "kind": "null" if extra.get("value") is None else "scalar",
        "type": extra.get("type"),
        "displayType": extra.get("noxenType") or _simple_type(extra.get("type")),
        "noxenType": extra.get("noxenType"),
        "value": extra.get("value"),
    }


def _intent_extra_children(node: dict) -> list[tuple[str | None, dict]]:
    children: list[tuple[str | None, dict]] = [
        ("Action", {"kind": "field", "value": node.get("action") or "None"}),
        ("Data (URI)", {"kind": "field", "value": node.get("data") or "None"}),
        ("Component", {"kind": "field", "value": node.get("component") or "None"}),
    ]
    if node.get("package"):
        children.append(("Package", {"kind": "field", "value": node.get("package")}))
    children.append(("Flags", {"kind": "field", "markup": _format_intent_flags(node.get("flags") or 0)}))
    for category in node.get("categories") or []:
        children.append(("Category", {"kind": "field", "value": category}))
    if node.get("categoriesTruncated"):
        children.append((None, {"kind": "status", "value": "additional categories omitted"}))
    extras = node.get("extras")
    if isinstance(extras, dict):
        children.append(("Extras", extras))
    for error in node.get("errors") or []:
        children.append((None, {"kind": "status", "value": error}))
    return children


def _extra_node_children(node: dict) -> list[tuple[str | None, dict]]:
    kind = node.get("kind")
    children: list[tuple[str | None, dict]] = []
    if kind == "bundle":
        for item in node.get("items") or []:
            if isinstance(item, dict) and isinstance(item.get("value"), dict):
                label = str(item.get("key") if item.get("key") is not None else "null")
                if item.get("keyTruncated"):
                    label += "…"
                children.append((label, item["value"]))
    elif kind in {"array", "list"}:
        for index, item in enumerate(node.get("items") or []):
            if isinstance(item, dict):
                children.append((f"[{index}]", item))
    elif kind == "intent":
        children.extend(_intent_extra_children(node))
    elif kind == "opaque":
        children.append((None, {"kind": "status", "value": "opaque object"}))

    omitted = node.get("omitted")
    if isinstance(omitted, int) and omitted > 0:
        children.append((None, {"kind": "status", "value": f"{omitted} additional items omitted"}))
    if node.get("error"):
        children.append((None, {"kind": "status", "value": node.get("error")}))
    return children


def _extra_node_header(label: str | None, node: dict) -> str:
    kind = node.get("kind")
    label_text = f"[bold]{_markup(label)}[/bold]" if label is not None else ""
    if kind == "status":
        return f"[dim]{_extra_display_text(node.get('value'))}[/dim]"
    if kind == "field":
        value = node.get("markup") if node.get("markup") is not None else _extra_display_text(node.get("value"))
        return f"[dim]{_markup(label or ''):<13} :[/dim] {value}"

    type_name = _extra_type_name(node)
    typed_label = f"{label_text} {_extra_type_markup(type_name)}".strip()
    if kind == "null":
        return f"{typed_label} : null"
    if kind == "scalar":
        raw = node.get("value")
        shown = _extra_display_text(raw)
        if str(node.get("noxenType") or type_name).lower() in {"string", "char"} and raw is not None:
            shown = f'"{shown}"'
        suffix = " [dim](truncated)[/dim]" if node.get("truncated") else ""
        return f"{typed_label} : {shown}{suffix}"
    if kind in {"bundle", "array", "list"}:
        count = node.get("count")
        if count is not None:
            noun = "item" if count == 1 else "items"
            return f"{typed_label} [dim]({_markup(count)} {noun})[/dim]"
        return typed_label
    if kind == "intent":
        return typed_label
    if kind == "reference":
        return f"{typed_label} : [dim]reference to #{_markup(node.get('referenceId'))}[/dim]"
    if kind == "opaque":
        # Preserve the complete class name: it is the only useful fact about an opaque value.
        opaque_type = node.get("type") or type_name
        return f"{label_text} {_extra_type_markup(str(opaque_type))}".strip()
    if kind == "truncated":
        return f"{typed_label} : [dim]{_extra_display_text(node.get('reason') or 'truncated')}[/dim]"
    if kind == "error":
        return f"{typed_label} : [dim]{_extra_display_text(node.get('reason') or 'unreadable value')}[/dim]"
    return f"{typed_label} : [dim]unsupported structured value[/dim]"


def _render_extra_node(
    lines: list[str],
    label: str | None,
    node: dict,
    prefix: str,
    is_last: bool,
    context: dict,
    depth: int,
) -> None:
    if context["lines"] >= _EXTRA_RENDER_MAX_LINES:
        return
    if depth > _EXTRA_RENDER_MAX_DEPTH:
        lines.append(_extra_tree_prefix(prefix, is_last) + "[dim]rendering depth limit reached[/dim]")
        context["lines"] += 1
        return
    if not isinstance(node, dict):
        node = {"kind": "error", "reason": "invalid structured value"}

    node_id = id(node)
    if node_id in context["active"]:
        lines.append(_extra_tree_prefix(prefix, is_last) + "[dim]invalid recursive model[/dim]")
        context["lines"] += 1
        return

    lines.append(_extra_tree_prefix(prefix, is_last) + _extra_node_header(label, node))
    context["lines"] += 1
    if context["lines"] >= _EXTRA_RENDER_MAX_LINES:
        return

    context["active"].add(node_id)
    try:
        children = _extra_node_children(node)
        child_prefix = prefix + ("   " if is_last else "│  ")
        for index, (child_label, child_node) in enumerate(children):
            _render_extra_node(
                lines,
                child_label,
                child_node,
                child_prefix,
                index == len(children) - 1,
                context,
                depth + 1,
            )
            if context["lines"] >= _EXTRA_RENDER_MAX_LINES:
                break
    finally:
        context["active"].discard(node_id)


def _extras_lines(extras: dict, metadata: dict | None = None) -> list[str]:
    metadata = metadata if isinstance(metadata, dict) else {}
    if not extras and not metadata.get("error") and not metadata.get("omitted"):
        return []

    count = metadata.get("count")
    if not isinstance(count, int):
        count = len(extras)
    lines = [f"{_section('EXTRAS')} ({count})"]
    roots: list[tuple[str | None, dict]] = []
    for key, extra in extras.items():
        extra = extra if isinstance(extra, dict) else {}
        structured = extra.get("structured")
        node = structured if isinstance(structured, dict) else _legacy_extra_node(extra)
        roots.append((str(key), node))
    omitted = metadata.get("omitted")
    if isinstance(omitted, int) and omitted > 0:
        roots.append((None, {"kind": "status", "value": f"{omitted} additional extras omitted"}))
    if metadata.get("error"):
        roots.append((None, {"kind": "status", "value": metadata.get("error")}))

    context = {"lines": 0, "active": set()}
    for index, (label, node) in enumerate(roots):
        _render_extra_node(lines, label, node, "  ", index == len(roots) - 1, context, 0)
        if context["lines"] >= _EXTRA_RENDER_MAX_LINES:
            lines.append("  [dim]… extra rendering limit reached[/dim]")
            break
    return lines


def _stack_lines(trace: list, stack_depth: int, show_empty: bool = False) -> list[str]:
    if not trace:
        return ["", _section("STACK TRACE"), "  [dim]No stack trace captured.[/dim]"] if show_empty else []
    lines = ["", _section("STACK TRACE")]
    for line in trace[:stack_depth]:
        lines.append(f"  [dim]{_markup(line)}[/dim]")
    if len(trace) > stack_depth:
        lines.append(f"  [dim]... (+{len(trace) - stack_depth} more)[/dim]")
    return lines


def _event_body(class_name, method, info: dict, attack_surface: dict, pending_flags_raw) -> list[str]:
    """The shared section stack: caller context, payload, pending intent, extras."""
    out = [_section("HOOK")]
    out += _hook_caller_lines(class_name, method, attack_surface)
    out.append("")
    out.append(_section("CAPTURED INTENT PAYLOAD"))
    out += _payload_lines(info, attack_surface)
    pending = _format_pending_flags(pending_flags_raw)
    if pending is not None:
        out += ["", _section("PENDING INTENT"), _row("Flags", pending)]
    extras = _extras_lines(info.get("extras") or {}, info.get("extrasMeta"))
    if extras:
        out.append("")
        out += extras
    return out


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
    return f"{hex_value}  \\[{_markup(' | '.join(decoded))}]"


def _changes_lines(original: dict, info: dict) -> list[str]:
    """The [CHANGES] diff for a modified-then-forwarded intent (History detail)."""
    out = ["", _section("CHANGES")]
    has_changes = False

    orig_action = original.get("action") or ""
    mod_action = info.get("action") or ""
    if orig_action != mod_action:
        has_changes = True
        out.append(_row("Action", f"[dim]{_markup(orig_action or '(none)')}[/dim] → {_markup(mod_action or '(none)')}"))

    orig_data = original.get("data") or ""
    mod_data = info.get("data") or ""
    if orig_data != mod_data:
        has_changes = True
        out.append(_row("Data (URI)", f"[dim]{_markup(orig_data or '(none)')}[/dim] → {_markup(mod_data or '(none)')}"))

    orig_categories = list(original.get("categories") or [])
    mod_categories = list(info.get("categories") or [])
    removed_categories = [c for c in orig_categories if c not in mod_categories]
    added_categories = [c for c in mod_categories if c not in orig_categories]
    if removed_categories or added_categories:
        has_changes = True
        out += ["", _section("CATEGORIES")]
        for category in removed_categories:
            out.append(f"  \\[-] [dim]{_markup(category)}[/dim]")
        for category in added_categories:
            out.append(f"  \\[+] {_markup(category)}")

    orig_extras = original.get("extras") or {}
    mod_extras = info.get("extras") or {}
    removed_keys = [k for k in orig_extras if k not in mod_extras]
    added_keys = [k for k in mod_extras if k not in orig_extras]
    changed_keys = [
        k for k in orig_extras
        if k in mod_extras and str(orig_extras[k].get("value", "")) != str(mod_extras[k].get("value", ""))
    ]
    if removed_keys or added_keys or changed_keys:
        has_changes = True
        out += ["", _section("EXTRAS")]
        for key in changed_keys:
            old_value, new_value = orig_extras[key], mod_extras[key]
            out.append(
                f"  \\[~] [bold]{_markup(key)}[/bold]  [dim]({_simple_type(old_value.get('type'))})[/dim]  "
                f"[dim]{_markup(old_value.get('value'))}[/dim] → {_markup(new_value.get('value'))}"
            )
        for key in removed_keys:
            value = orig_extras[key]
            out.append(
                f"  \\[-] [bold]{_markup(key)}[/bold]  [dim]({_simple_type(value.get('type'))})[/dim]  "
                f"[dim]{_markup(value.get('value'))}[/dim]"
            )
        for key in added_keys:
            value = mod_extras[key]
            out.append(f"  \\[+] [bold]{_markup(key)}[/bold]  [dim]({_simple_type(value.get('type'))})[/dim]  {_markup(value.get('value'))}")

    if not has_changes:
        out.append("  [dim](forwarded without changes)[/dim]")
    return out


def render_intercept_block(payload: dict, intercept_counter: int, show_stack: bool, stack_depth: int) -> str:
    info = payload.get("infoIntent", {}) or {}
    attack_surface = payload.get("attackSurface") or {}

    out = [
        "[bold #F2C94C]" + "━" * 50 + "[/bold #F2C94C]",
        f"[bold]INTERCEPTED #{intercept_counter}[/bold]",
        "",
    ]
    out += _event_body(
        payload.get("className"), payload.get("methodName"), info, attack_surface, payload.get("pendingIntentFlags")
    )
    if show_stack:
        out += _stack_lines(payload.get("stackTrace") or [], stack_depth)
    out.append("")
    return "\n".join(out)


def render_intent_detail(entry: dict, show_stack: bool = False, stack_depth: int = 15) -> str:
    info = entry.get("intent", {}) or {}
    attack_surface = entry.get("attackSurface") or {}
    outcome_label = _OUTCOME_LABEL.get(entry.get("outcome") or "", "PENDING")
    timestamp = entry.get("timestamp", "")
    time_str = timestamp[:19].replace("T", " ") if len(timestamp) >= 19 else timestamp

    out = [
        "",
        f"[bold]#{entry['id']}[/bold] [dim]|[/dim] {_markup(time_str)} [dim]|[/dim] {outcome_label}",
        "",
    ]
    out += _event_body(
        entry.get("class"), entry.get("method"), info, attack_surface, entry.get("pendingIntentFlags")
    )
    if entry.get("original_intent"):
        out += _changes_lines(entry["original_intent"], info)
    if show_stack:
        out += _stack_lines(entry.get("stackTrace") or [], stack_depth, show_empty=True)
    out.append("")
    return "\n".join(out)
