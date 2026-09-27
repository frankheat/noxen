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


# ------------------------------------------------------------------
# Access classification
# ------------------------------------------------------------------

ACCESS_OPEN = "open"
ACCESS_WEAK = "weak"
ACCESS_PROTECTED = "protected"
_ACCESS_RANK = {ACCESS_OPEN: 0, ACCESS_WEAK: 1, ACCESS_PROTECTED: 2}

# Protection level → the barrier it puts in front of other apps. Anything else
# ("normal", "unresolved", "unknown") is open: normal is granted to any requester,
# and an unresolved permission may be undefined and claimable by any app.
_LEVEL_ACCESS = {
    "dangerous": ACCESS_WEAK,
    "signature": ACCESS_PROTECTED,
    "signatureOrSystem": ACCESS_PROTECTED,
    "internal": ACCESS_PROTECTED,
}


def permission_access(permission: dict | None) -> str:
    """open / weak / protected for a single {name, level} permission (None = open)."""
    if not permission:
        return ACCESS_OPEN
    return _LEVEL_ACCESS.get(permission.get("level"), ACCESS_OPEN)


def _weakest(accesses) -> str:
    return min(accesses, key=_ACCESS_RANK.__getitem__)


def provider_access(component: dict) -> dict:
    """Per-direction access of a provider: {"read": ..., "write": ...}.

    A direction is guarded by the provider's read/write permission; a matching
    <path-permission> is an alternative grant for its paths, so the weakest wins.
    """
    result = {}
    for direction, key in (("read", "readPermission"), ("write", "writePermission")):
        accesses = [permission_access(component.get(key))]
        for path in component.get("pathPermissions") or []:
            if path.get(key):
                accesses.append(permission_access(path.get(key)))
        result[direction] = _weakest(accesses)
    return result


def component_access(component: dict) -> str | None:
    """open / weak / protected for an exported component; None when not exported.

    A provider takes its weakest direction: it is open if either reads or writes are.
    """
    if not component.get("exported"):
        return None
    if component.get("type") == "provider":
        return _weakest(provider_access(component).values())
    return permission_access(component.get("permission"))


def is_exposed(component: dict) -> bool:
    """Reachable by other apps with little/no barrier: exported with open access."""
    return component_access(component) == ACCESS_OPEN


def component_permissions(component: dict) -> list[dict]:
    """Every permission guarding a component (provider read/write and path ones included)."""
    perms = [component.get("permission"), component.get("readPermission"), component.get("writePermission")]
    for path in component.get("pathPermissions") or []:
        perms += [path.get("readPermission"), path.get("writePermission")]
    return [perm for perm in perms if perm]


def format_permission(permission: dict | None, own_package: str | None = None) -> str:
    """`name (level)`; with own_package, also names a third-party defining package."""
    if not permission:
        return "—"
    name = permission.get("name") or ""
    parts = [permission.get("level")] if permission.get("level") else []
    defined_by = permission.get("definedBy")
    if own_package and defined_by and defined_by not in (own_package, "android"):
        parts.append(f"defined by {defined_by}")
    return f"{name} ({' · '.join(parts)})" if parts else name


def format_component_permission(component: dict) -> str:
    """Permission cell of the Components table.

    A provider guarded by one permission for both directions (android:permission) shows
    it like any component; otherwise the cell summarises the level per direction and the
    path permissions, leaving the names to the detail panel.
    """
    if component.get("type") != "provider":
        return format_permission(component.get("permission"))
    read, write = component.get("readPermission"), component.get("writePermission")
    paths = component.get("pathPermissions") or []
    if not (read or write or paths):
        return "—"
    if read and write and read.get("name") == write.get("name") and not paths:
        return format_permission(read)

    def level(permission):
        return (permission.get("level") or "?") if permission else "—"

    text = f"read: {level(read)} · write: {level(write)}"
    if paths:
        text += f" · +{len(paths)} path{'s' if len(paths) > 1 else ''}"
    return text


# ------------------------------------------------------------------
# Table rows
# ------------------------------------------------------------------

def component_row(component: dict) -> list[str]:
    return [
        component.get("name") or "",
        component.get("type") or "",
        _yesno(component.get("exported")),
        component_access(component) or "—",
        _yesno(component_enabled(component)),
        # last: it can be long, and the short columns before it stay visible
        format_component_permission(component),
    ]


def permission_row(permission: dict) -> list[str]:
    granted = permission.get("granted")
    granted_str = "—" if granted is None else _yesno(granted)
    return [
        permission.get("name") or "",
        permission.get("source") or "",
        granted_str,
        permission.get("level") or "",
        permission.get("definedBy") or "—",
    ]


# ------------------------------------------------------------------
# Search / filter
# ------------------------------------------------------------------

def component_matches(component: dict, query: str) -> bool:
    q = query.lower()
    fields = [
        component.get("name") or "",
        component.get("type") or "",
        component.get("authority") or "",
    ]
    fields += [perm.get("name") or "" for perm in component_permissions(component)]
    return any(q in str(field).lower() for field in fields)


def permission_matches(permission: dict, query: str) -> bool:
    q = query.lower()
    return any(q in str(permission.get(key) or "").lower() for key in ("name", "source", "level", "definedBy"))


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
# Sorting
# ------------------------------------------------------------------

# (key, header label) in display order; keys are the sort columns below and must
# match the cell order of component_row / permission_row.
COMPONENT_COLUMNS = [
    ("name", "Name"), ("type", "Type"), ("exported", "Exported"),
    ("access", "Access"), ("enabled", "Enabled"), ("permission", "Permission"),
]
PERMISSION_COLUMNS = [
    ("name", "Permission"), ("source", "Source"), ("granted", "Granted"),
    ("level", "Level"), ("definedBy", "Defined by"),
]

# Semantic orders: ascending goes from the most exposed to the most protected.
_TYPE_ORDER = {"activity": 0, "service": 1, "receiver": 2, "provider": 3}
# None = not exported: a real value (unreachable, so after protected), not an empty cell.
_ACCESS_ORDER = {ACCESS_OPEN: 0, ACCESS_WEAK: 1, ACCESS_PROTECTED: 2, None: 3}
_LEVEL_ORDER = {"unresolved": 0, "unknown": 1, "normal": 2, "dangerous": 3,
                "signature": 4, "signatureOrSystem": 5, "internal": 6}


def component_sort_value(component: dict, column: str):
    """Sort value of a Components column; None marks an empty cell."""
    if column == "type":
        return _TYPE_ORDER.get(component.get("type"), len(_TYPE_ORDER))
    if column == "exported":
        return 0 if component.get("exported") else 1
    if column == "access":
        return _ACCESS_ORDER[component_access(component)]
    if column == "enabled":
        return 0 if component_enabled(component) else 1
    if column == "permission":
        cell = format_component_permission(component)
        return None if cell == "—" else cell.lower()
    return (component.get("name") or "").lower()


def permission_sort_value(permission: dict, column: str):
    """Sort value of a Permissions column; None marks an empty cell."""
    if column == "source":
        return permission.get("source") or None
    if column == "granted":
        granted = permission.get("granted")
        return None if granted is None else (0 if granted else 1)
    if column == "level":
        level = permission.get("level")
        return None if not level else _LEVEL_ORDER.get(level, len(_LEVEL_ORDER))
    if column == "definedBy":
        return (permission.get("definedBy") or "").lower() or None
    return (permission.get("name") or "").lower()


def _sort_rows(items, value, reverse: bool, tie_key) -> list:
    """Sort by `value`, ties by name (always ascending), empty cells always last."""
    ordered = sorted(items or [], key=tie_key)
    present = [item for item in ordered if value(item) is not None]
    empty = [item for item in ordered if value(item) is None]
    present.sort(key=value, reverse=reverse)  # stable: ties keep the name order
    return present + empty


def sort_components(components, column: str | None, reverse: bool = False) -> list:
    if not column:
        return list(components or [])
    return _sort_rows(components, lambda c: component_sort_value(c, column), reverse,
                      lambda c: (c.get("name") or "").lower())


def sort_permissions(permissions, column: str | None, reverse: bool = False) -> list:
    if not column:
        return list(permissions or [])
    return _sort_rows(permissions, lambda p: permission_sort_value(p, column), reverse,
                      lambda p: ((p.get("name") or "").lower(), p.get("source") or ""))


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
    unresolved = sum(1 for p in requested if p.get("level") == "unresolved")

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
        ("Access", f"open {counts[ACCESS_OPEN]} · weak {counts[ACCESS_WEAK]}"
                   f" · protected {counts[ACCESS_PROTECTED]}"),
        ("Permissions", f"requested {len(requested)} (granted {granted}) · defined {defined}"
                        + (f" · unresolved {unresolved}" if unresolved else "")),
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
    """Per-type counts, exported count, and the access class of exported components."""
    counts = {"activity": 0, "service": 0, "receiver": 0, "provider": 0, "exported": 0,
              ACCESS_OPEN: 0, ACCESS_WEAK: 0, ACCESS_PROTECTED: 0}
    for component in components or []:
        counts[component.get("type")] = counts.get(component.get("type"), 0) + 1
        if component.get("exported"):
            counts["exported"] += 1
        access = component_access(component)
        if access:
            counts[access] += 1
    return counts


# ------------------------------------------------------------------
# Component detail
# ------------------------------------------------------------------

_UNRESOLVED_NOTE = [
    "unresolved: no package defines it (any app could define and claim it), or its",
    "defining app is hidden by package visibility. Check: adb shell pm list permissions -f",
]


def render_component_detail(component: dict, own_package: str | None = None) -> str:
    out = [
        f"[bold]{_markup(component.get('name'))}[/bold]  [dim]· {_markup(component.get('type'))}[/dim]",
        "",
    ]

    def row(label, value):
        out.append(f"  [dim]{label:<18}[/dim] {value}")

    def perm(permission):
        return _markup(format_permission(permission, own_package))

    def path_of(entry):
        return f"{_markup(entry.get('match'))} {_markup(entry.get('path'))}"

    component_type = component.get("type")
    access = component_access(component)
    row("Exported", _yesno(component.get("exported")))
    if component_type == "provider":
        directions = provider_access(component)
        detail = f"  [dim](read: {directions['read']} · write: {directions['write']})[/dim]" if access else ""
        row("Access", f"{access or '—'}{detail}")
    else:
        row("Access", access or "—")
        row("Permission", perm(component.get("permission")))
    runtime = component.get("enabledRuntime")
    enabled = _yesno(component_enabled(component))
    if runtime:
        enabled += f"  [dim](runtime: {_ENABLED_RUNTIME.get(runtime, '?')})[/dim]"
    row("Enabled", enabled)
    row("Process", _markup(component.get("processName") or "—"))
    if component.get("directBootAware"):
        row("Direct boot aware", "yes")

    if component_type == "activity":
        if component.get("targetActivity"):
            row("Target activity", f"{_markup(component.get('targetActivity'))}  [dim](alias)[/dim]")
        row("Launch mode", _markup(component.get("launchMode")))
        row("Task affinity", _markup(component.get("taskAffinity") or "—"))
    elif component_type == "service" and component.get("foregroundServiceType"):
        row("FGS type", _markup(component.get("foregroundServiceType")))
    elif component_type == "provider":
        row("Authority", _markup(component.get("authority") or "—"))
        row("Read permission", perm(component.get("readPermission")))
        row("Write permission", perm(component.get("writePermission")))
        for index, entry in enumerate(component.get("pathPermissions") or []):
            row("Path permissions" if index == 0 else "",
                f"{path_of(entry)}  [dim]read:[/dim] {perm(entry.get('readPermission'))}"
                f"  [dim]write:[/dim] {perm(entry.get('writePermission'))}")
        row("Grant URI perms", _yesno(component.get("grantUriPermissions")))
        for index, entry in enumerate(component.get("grantUriPatterns") or []):
            row("Grant URI paths" if index == 0 else "", path_of(entry))
        if component.get("multiprocess"):
            row("Multiprocess", "yes")

    if any(p.get("level") == "unresolved" for p in component_permissions(component)):
        out.append("")
        out.extend(f"  [dim]{line}[/dim]" for line in _UNRESOLVED_NOTE)

    return "\n".join(out)
