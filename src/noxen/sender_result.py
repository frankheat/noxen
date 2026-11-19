"""Human-readable Sender results derived from an unchanged run snapshot."""

from rich import box
from rich.table import Table
from rich.text import Text
from rich.tree import Tree


def _value(value):
    if value is None:
        return "null"
    if value == "":
        return '""'
    return str(value)


def _cell(cell):
    if not isinstance(cell, dict):
        return Text(_value(cell))
    if cell.get("captured") is False:
        kind = "BLOB · " if cell.get("type") == "blob" else ""
        return Text(kind + "Not captured", style="dim")
    value = Text(_value(cell.get("value")))
    if cell.get("truncated"):
        value.append(" (truncated)", style="dim")
    return value


class CapturedRows:
    """Bound the display, not the data. Raw always has the full saved result."""

    MAX_ROWS = 40
    MAX_COLUMNS = 8

    def __init__(self, columns, rows):
        self.columns, self.rows = columns, rows

    def __rich_console__(self, console, options):
        col_count = min(len(self.columns), self.MAX_COLUMNS, max(1, (options.max_width - 6) // 10))
        row_count = min(len(self.rows), self.MAX_ROWS)
        if row_count < len(self.rows) or col_count < len(self.columns):
            yield Text(f"Preview: {row_count}/{len(self.rows)} rows · {col_count}/{len(self.columns)} columns. "
                       "See Raw for all captured values.", style="dim")
        table = Table(box=box.SIMPLE, show_edge=False, pad_edge=False, padding=(0, 1), header_style="dim")
        table.add_column("#", justify="right", no_wrap=True)
        for name in self.columns[:col_count]:
            table.add_column(Text(str(name)), max_width=32)
        for i, row in enumerate(self.rows[:row_count], 1):
            table.add_row(str(i), *[_cell(row[j]) if j < len(row) else Text("Unavailable", style="dim")
                                    for j in range(col_count)])
        yield table


def _bundle(payload):
    if not isinstance(payload, dict):
        return Text("null" if payload is None else "Unrecognized Bundle"), payload is not None
    values = payload.get("values")
    incomplete = payload.get("captured") is False or bool(payload.get("truncated"))
    if not isinstance(values, dict):
        if not incomplete:
            return Text("Unrecognized Bundle", style="dim"), True
        values = {}
    tree = Tree(Text("Bundle"), guide_style="dim")
    for key, item in values.items():
        if not isinstance(item, dict):
            incomplete = True
            tree.add(Text(f"{key}: Unrecognized value", style="dim"))
            continue
        kind = str(item.get("type") or "unknown").removeprefix("java.lang.")
        label = Text(f"{key} ").append(f"[{kind}]", style="dim")
        if kind == "android.os.Bundle" and item.get("captured") is not False:
            child, partial = _bundle(item.get("value"))
            incomplete |= partial
            if isinstance(child, Tree):
                branch = tree.add(label)
                branch.children.extend(child.children)
            else:
                tree.add(label.append(": ").append_text(child))
        else:
            incomplete |= item.get("captured") is False or bool(item.get("truncated"))
            tree.add(label.append(": ").append_text(_cell(item)))
    if not values and not incomplete:
        return Text("Empty Bundle", style="dim"), False
    if incomplete:
        reason = payload.get("reason") or payload.get("error")
        tree.label.append(" · Partial capture", style="dim")
        if reason:
            tree.add(Text(str(reason), style="dim"))
    return tree, incomplete


def summarize_result(operation, record):
    """Return a state, labeled fields and optional renderables, without inferring delivery."""
    state = record.get("state")
    result = record.get("result")
    if state != "returned":
        return {
            "preparing": "Preparing", "running": "Running", "error": "Android exception",
            "unknown": "Outcome unknown", "cancelled": "Cancelled by Android",
        }.get(state, str(state)), [], []
    if isinstance(result, dict) and result.get("captured") is False:
        reason = result.get("reason")
        return "Call returned · Result not captured", [("Reason", reason)] if reason else [], []
    if operation == "startActivity":
        return "Call returned · Activity launch unverified", [], []
    if operation == "sendBroadcast":
        return "Call returned · Delivery unverified", [], []
    if not isinstance(result, dict):
        return "Call returned", [], []
    kind, value = result.get("kind"), result.get("value")
    if operation == "sendOrderedBroadcast" and kind == "broadcastResult":
        extras = result.get("extras")
        detail, partial = _bundle(extras)
        fields = [("Result code", _value(result.get("code"))), ("Data", _value(result.get("data")))]
        fields.append(("Extras", "null" if extras is None else "Partial capture" if partial else "Bundle"))
        content = [] if extras is None else [detail]
        if result.get("code") == 0 and result.get("data") is None and extras is None:
            content.append(Text("Result matches the initial values · Receiver delivery unverified", style="dim"))
        return "Final callback received", fields, content
    if operation in ("startService", "startForegroundService") and kind == "component" and "value" in result:
        if value is None:
            return "Call returned · No component returned", [], []
        return "Call returned · Component returned", [("Component", value)], []
    if operation == "stopService" and kind == "boolean" and type(value) is bool:
        return "Service stopped" if value else "No matching running service", [], []
    if operation == "query" and kind == "cursor":
        if "value" in result and value is None:
            return "Call returned · No cursor returned", [], []
        columns, rows = result.get("columns"), result.get("rows")
        if not isinstance(columns, list) or not isinstance(rows, list) or not all(isinstance(row, list) for row in rows):
            if result.get("truncated"):
                reason = result.get("reason") or "Capture limit reached"
                return "Call returned · Result not captured", [("Reason", reason)], []
            return "Call returned", [], []
        omitted = sum(isinstance(cell, dict) and cell.get("captured") is False for row in rows for cell in row)
        truncated = sum(isinstance(cell, dict) and bool(cell.get("truncated")) for row in rows for cell in row)
        partial = result.get("truncated") or omitted or truncated
        state = f"{len(rows)} {'row' if len(rows) == 1 else 'rows'} captured"
        fields = []
        if result.get("truncated"):
            fields.append(("Reason", result.get("reason") or "Row or byte limit reached"))
        if omitted:
            fields.append(("Cells not captured", omitted))
        if truncated:
            fields.append(("Cells truncated", truncated))
        return state + (" · Partial result" if partial else ""), fields, [CapturedRows(columns, rows)] if rows else []
    label = {
        ("getType", "String"): "MIME type", ("insert", "uri"): "Returned URI",
        ("update", "int"): "Rows updated", ("delete", "int"): "Rows deleted",
    }.get((operation, kind))
    if label and "value" in result:
        if value is None and operation in ("getType", "insert"):
            name = "MIME type" if operation == "getType" else "URI"
            return f"Call returned · No {name} returned", [], []
        return "Call returned", [(label, _value(value))], []
    if operation == "call" and kind == "Bundle" and "value" in result:
        if value is None:
            return "Call returned · No Bundle returned", [], []
        detail, partial = _bundle(value)
        return "Bundle returned" + (" · Partial capture" if partial else ""), [], [detail]
    if operation == "openFileDescriptor" and kind == "file" and "value" in result:
        if value is None:
            return "Call returned · No file descriptor returned", [], []
        state = "File read · Partial capture" if result.get("truncated") else "File read · Complete"
        return state, [("Bytes captured", result.get("bytes")), ("Encoding", "Base64" if result.get("encoding") == "base64"
                                                               else result.get("encoding"))], []
    return "Call returned", [], []
