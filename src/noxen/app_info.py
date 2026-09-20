"""Pure helpers for the Info app tab: shape the `getAppInfo` snapshot into
overview rows, table rows, detail text, and search/filter results.

No Textual/Frida imports — everything here is unit-testable on the raw snapshot dict
returned by the agent's `getAppInfo` RPC.
"""

from datetime import datetime, timezone

from rich.markup import escape


# PackageManager.COMPONENT_ENABLED_STATE_* → label
_ENABLED_RUNTIME = {
    0: "default",
    1: "enabled",
    2: "disabled",
    3: "disabled (user)",
    4: "disabled (until used)",
}


def _markup(value) -> str:
    return "" if value is None else escape(str(value))


def _yesno(value) -> str:
    return "yes" if value else "no"


def _epoch_ms(value) -> str:
    try:
        return datetime.fromtimestamp(int(value) / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError, OverflowError, OSError):
        return "—"


def format_sha256(digests) -> str:
    if not digests:
        return "—"
    first = str(digests[0])
    grouped = ":".join(first[i:i + 2] for i in range(0, len(first), 2))
    extra = f"  (+{len(digests) - 1} more)" if len(digests) > 1 else ""
    return grouped + extra


def component_enabled(component: dict) -> bool:
    """Effective enabled state: the runtime override wins over the manifest default."""
    runtime = component.get("enabledRuntime")
    if runtime == 1:
        return True
    if runtime in (2, 3, 4):
        return False
    return bool(component.get("enabled"))


def is_exposed(component: dict) -> bool:
    """Reachable by other apps with little/no barrier: exported + no or `normal` permission."""
    if not component.get("exported"):
        return False
    permission = component.get("permission")
    level = (permission or {}).get("level")
    return permission is None or level == "normal"


def format_permission(permission: dict | None) -> str:
    if not permission:
        return "—"
    name = permission.get("name") or ""
    level = permission.get("level")
    return f"{name} ({level})" if level else name


# ------------------------------------------------------------------
# Table rows
# ------------------------------------------------------------------

def component_row(component: dict) -> list[str]:
    return [
        component.get("name") or "",
        component.get("type") or "",
        _yesno(component.get("exported")),
        format_permission(component.get("permission")),
        _yesno(component_enabled(component)),
    ]


def permission_row(permission: dict) -> list[str]:
    granted = permission.get("granted")
    granted_str = "—" if granted is None else _yesno(granted)
    return [
        permission.get("name") or "",
        permission.get("source") or "",
        granted_str,
        permission.get("level") or "",
    ]


# ------------------------------------------------------------------
# Search / filter
# ------------------------------------------------------------------

def component_matches(component: dict, query: str) -> bool:
    q = query.lower()
    fields = [
        component.get("name") or "",
        component.get("type") or "",
        (component.get("permission") or {}).get("name") or "",
        component.get("authority") or "",
    ]
    return any(q in str(field).lower() for field in fields)


def permission_matches(permission: dict, query: str) -> bool:
    q = query.lower()
    return any(q in str(permission.get(key) or "").lower() for key in ("name", "source", "level"))


def filter_components(components, query: str = "", type_filter: str | None = None, exposed_only: bool = False) -> list:
    result = []
    for component in components or []:
        if type_filter and component.get("type") != type_filter:
            continue
        if exposed_only and not is_exposed(component):
            continue
        if query and not component_matches(component, query):
            continue
        result.append(component)
    return result


def filter_permissions(permissions, query: str = "", source: str | None = None) -> list:
    result = []
    for permission in permissions or []:
        if source and permission.get("source") != source:
            continue
        if query and not permission_matches(permission, query):
            continue
        result.append(permission)
    return result


# ------------------------------------------------------------------
# Overview
# ------------------------------------------------------------------

def overview_sections(info: dict) -> list[tuple[str, list[tuple[str, str]]]]:
    """Grouped (label, value) rows for the Overview sub-view."""
    identity = info.get("identity") or {}
    build = info.get("build") or {}
    signing = info.get("signing") or {}
    components = info.get("components") or []
    permissions = info.get("permissions") or []

    counts = component_counts(components)
    requested = [p for p in permissions if p.get("source") == "requested"]
    granted = sum(1 for p in requested if p.get("granted"))
    defined = sum(1 for p in permissions if p.get("source") == "defined")

    def num(value):
        return str(value) if value is not None else "—"

    identity_rows = [
        ("Package", identity.get("package") or "—"),
        ("Label", identity.get("label") or "—"),
        ("Version", f"{identity.get('versionName') or '—'} ({identity.get('versionCode') or '—'})"),
        ("UID", num(identity.get("uid"))),
        ("PID", num(identity.get("pid"))),
        ("Process", identity.get("processName") or "—"),
        ("sharedUserId", identity.get("sharedUserId") or "—"),
        ("Installer", identity.get("installer") or "—"),
        ("First install", _epoch_ms(identity.get("firstInstallTime"))),
        ("Last update", _epoch_ms(identity.get("lastUpdateTime"))),
    ]
    build_rows = [
        ("Target SDK", num(build.get("targetSdk"))),
        ("Min SDK", num(build.get("minSdk"))),
        ("Compile SDK", num(build.get("compileSdk"))),
        ("Debuggable", _yesno(build.get("debuggable"))),
        ("Allow backup", _yesno(build.get("allowBackup"))),
        ("Cleartext traffic", _yesno(build.get("cleartextPermitted"))),
        ("Test only", _yesno(build.get("testOnly"))),
        ("Network Security Config", _yesno(build.get("nscPresent"))),
    ]
    signing_rows = [
        ("Signer SHA-256", format_sha256(signing.get("sha256"))),
        ("Multiple signers", _yesno(signing.get("multipleSigners"))),
    ]
    summary_rows = [
        ("Components", f"{len(components)}  (activities {counts['activity']} · services {counts['service']}"
                       f" · receivers {counts['receiver']} · providers {counts['provider']})"),
        ("Exported", str(counts["exported"])),
        ("Exposed", str(counts["exposed"])),
        ("Permissions", f"requested {len(requested)} (granted {granted}) · defined {defined}"),
    ]
    return [
        ("IDENTITY", identity_rows),
        ("BUILD & FLAGS", build_rows),
        ("SIGNING", signing_rows),
        ("SUMMARY", summary_rows),
    ]


def render_overview(info: dict) -> str:
    """Full Rich markup for the Overview sub-view (grouped `label : value` rows)."""
    out = []
    for title, rows in overview_sections(info):
        out.append(f"[bold]\\[{title}][/bold]")
        for label, value in rows:
            out.append(f"  [dim]{label:<24}[/dim] {_markup(value)}")
        out.append("")
    return "\n".join(out)


def component_counts(components) -> dict:
    counts = {"activity": 0, "service": 0, "receiver": 0, "provider": 0, "exported": 0, "exposed": 0}
    for component in components or []:
        counts[component.get("type")] = counts.get(component.get("type"), 0) + 1
        if component.get("exported"):
            counts["exported"] += 1
        if is_exposed(component):
            counts["exposed"] += 1
    return counts


# ------------------------------------------------------------------
# Component detail
# ------------------------------------------------------------------

def render_component_detail(component: dict) -> str:
    out = [
        f"[bold]{_markup(component.get('name'))}[/bold]  [dim]· {_markup(component.get('type'))}[/dim]",
        "",
    ]

    def row(label, value):
        out.append(f"  [dim]{label:<18}[/dim] {value}")

    row("Exported", _yesno(component.get("exported")))
    row("Permission", _markup(format_permission(component.get("permission"))))
    runtime = component.get("enabledRuntime")
    enabled = _yesno(component_enabled(component))
    if runtime:
        enabled += f"  [dim](runtime: {_ENABLED_RUNTIME.get(runtime, '?')})[/dim]"
    row("Enabled", enabled)
    row("Process", _markup(component.get("processName") or "—"))
    if component.get("directBootAware"):
        row("Direct boot aware", "yes")

    component_type = component.get("type")
    if component_type == "activity":
        if component.get("targetActivity"):
            row("Target activity", f"{_markup(component.get('targetActivity'))}  [dim](alias)[/dim]")
        row("Launch mode", _markup(component.get("launchMode")))
        row("Task affinity", _markup(component.get("taskAffinity") or "—"))
    elif component_type == "service" and component.get("foregroundServiceType"):
        row("FGS type", _markup(component.get("foregroundServiceType")))
    elif component_type == "provider":
        row("Authority", _markup(component.get("authority") or "—"))
        row("Read permission", _markup(component.get("readPermission") or "—"))
        row("Write permission", _markup(component.get("writePermission") or "—"))
        row("Grant URI perms", _yesno(component.get("grantUriPermissions")))
        if component.get("multiprocess"):
            row("Multiprocess", "yes")

    return "\n".join(out)
