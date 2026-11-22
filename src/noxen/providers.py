"""Provider History entries and the common section-based detail layout."""
import json
from datetime import datetime, timezone

from rich.cells import cell_len
from rich.markup import escape
from noxen.rendering import capture_datetime, capture_order, capture_order_label, format_capture_time, format_detail_timestamp
from noxen.sender import validate_request
from noxen.sender_capture import capture_hook_label
from noxen.provider_fields import ordered_provider_arguments, ordered_provider_request


def provider_as_json(entry):
    """Present a capture with Sender request fields and separate response data."""
    record = entry["provider"]
    original = ordered_provider_arguments(record.get("arguments", {}))
    arguments = ordered_provider_arguments(record.get("sentArguments", original))
    view = {}
    if hook := capture_hook_label(entry):
        view["hook"] = hook
    if opaque := record.get("opaqueArguments"):
        view["notCaptured"] = [
            f"Argument {item['index'] + 1} ({item['type']})" for item in opaque
        ]
    try:
        request = provider_request(record)
        validate_request(request)
    except (KeyError, TypeError, ValueError):
        view["arguments"] = arguments
    else:
        view.update(request)
    if "callingUid" in record:
        view["callingUid"] = record["callingUid"]
    if arguments != original:
        view["originalArguments"] = original

    result = record.get("result") or {}
    response = {key: result[key] for key in ("type", "value") if key in result}
    response.update({key: result[key] for key in sorted(result) if key not in response})
    opaque_result = response.pop("opaque", False)
    for key in ("cursor", "cursorPreview", "cursorPreviewError", "exception"):
        if record.get(key) is not None:
            response[key] = record[key]
    if record.get("sentCursor") is not None and record["sentCursor"] != record.get("cursor"):
        response["sentCursor"] = record["sentCursor"]
    if "sentResult" in record:
        response["sentValue"] = record["sentResult"]["value"]
    if opaque_result and not any(key in response for key in ("value", "cursor", "cursorPreview", "sentCursor")):
        note = "Cursor rows not read" if record.get("method") == "query" else "Response contents"
        view.setdefault("notCaptured", []).append(note)
    if response:
        view["response"] = response
    if record.get("error"):
        view["error"] = record["error"]
    return view


def provider_entry(record, connection):
    captured = capture_datetime(record.get("time")) or datetime.now(timezone.utc)
    decision = record.get("requestDecision", record.get("decision"))
    response = record.get("responseDecision")
    outcome = "dropped" if record.get("state") == "dropped" else (
        "modified_forwarded" if "modified_forwarded" in (decision, response) else
        "forwarded" if decision or record.get("state") in ("returned", "exception") else None)
    return {"class": record.get("class"), "method": record.get("method"), "intent": {},
            "timestamp": captured.isoformat(), "stackTrace": record.get("stackTrace", []),
            "outcome": outcome, "provider": dict(record, connection=connection),
            **capture_order(record),
            **({"released_at": record["releasedAt"]} if record.get("releasedAt") is not None else {})}


def _cursor_cell(cell):
    kind, value = cell["type"], cell["value"]
    if kind == "integer":
        return str(value)
    if kind == "omitted":
        return "<" + json.dumps(value, ensure_ascii=False)[1:-1] + ">"
    return json.dumps(value, ensure_ascii=False)


def _cursor_table(table):
    columns = [json.dumps(name, ensure_ascii=False)[1:-1] for name in table["columns"]]
    rows = [[_cursor_cell(cell) for cell in cells] for cells in table["rows"]]
    return _detail_table(columns, rows)


def _detail_table(columns, rows):
    if not rows:
        return ["[dim]  No rows[/dim]"]

    widths = [max(cell_len(value) for value in column) for column in zip(columns, *rows)]

    def line(values):
        padded = [value + " " * (width - cell_len(value)) for value, width in zip(values, widths)]
        return "  " + "  ".join(padded).rstrip()

    return [
        f"[bold]{escape(line(columns))}[/bold]",
        "[dim]" + line(["─" * width for width in widths]) + "[/dim]",
        *(escape(line(values)) for values in rows),
    ]


def _argument_lines(arguments, row):
    out = []
    values_table = []
    for key, value in arguments.items():
        if key == "values" and isinstance(value, dict):
            out.append(row(key, f"ContentValues ({len(value)} items)"))
            cells = []
            for name, item in value.items():
                if item["type"] in ("long", "int", "short", "byte") and item["value"] is not None:
                    text = str(item["value"])
                else:
                    text = json.dumps(item["value"], ensure_ascii=False)
                cells.append([json.dumps(name, ensure_ascii=False)[1:-1], item["type"], text])
            values_table = _detail_table(["Key", "Type", "Value"], cells)
        else:
            if key == "queryArguments" and isinstance(value, dict):
                out.append(row(key, "Bundle"))
                for name, item in value.items():
                    out.append("  " + row(name, json.dumps(item, ensure_ascii=False)))
            else:
                out.append(row(key, json.dumps(value, ensure_ascii=False)))
    if values_table:
        out += ["", *values_table]
    return out


def render_provider(entry):
    record = entry["provider"]
    preview = record.get("cursorPreview")
    arguments = ordered_provider_arguments(record.get("sentArguments", record.get("arguments", {})))
    original_arguments = ordered_provider_arguments(record.get("arguments", {}))
    label_width = max(13, max((cell_len(key) for key in (*arguments, *original_arguments)), default=0))

    def row(label, value):
        padding = " " * (label_width - cell_len(label))
        return f"[dim]  {escape(label)}{padding} :[/dim] {escape(str(value))}"
    order = capture_order_label(entry)
    timestamp = format_detail_timestamp(entry["timestamp"], has_capture_order=bool(order))
    out = ["", f"[bold]#{entry['id']}[/bold] [dim]|[/dim] {escape(timestamp)} [dim]|[/dim] {escape(record['state'].upper())}"]
    if order:
        out += ["", row("Capture order", order)]
    out += ["", "[bold]\\[HOOK][/bold]", row("Class", entry["class"]), row("Method", entry["method"]),
            row("Direction", record["direction"])]
    if record.get("state") == "held":
        out.append(row("Phase", record.get("phase", "request")))
    if "callingUid" in record:
        out.append(row("Calling UID", record["callingUid"]))
    out += ["", "[bold]\\[REQUEST][/bold]"]
    out += _argument_lines(arguments, row)
    if record.get("sentArguments") != record.get("arguments") and "sentArguments" in record:
        out += ["", "[bold]\\[ORIGINAL REQUEST][/bold]", *_argument_lines(original_arguments, row)]
    finished_at = record.get("finishedAt")
    if "result" in record or finished_at is not None:
        out += ["", "[bold]\\[RESPONSE][/bold]"]
    if "result" in record:
        out.append(row("Type", record["result"].get("type")))
        if "value" in record["result"]:
            out.append(row("Value", json.dumps(record["result"]["value"], ensure_ascii=False)))
            if "sentResult" in record:
                out.append(row("Sent value", json.dumps(record["sentResult"]["value"], ensure_ascii=False)))
        elif record.get("cursor") is None and preview is None:
            if record.get("method") == "query":
                preview_error = record.get("cursorPreviewError")
                out.append(row("Contents", "Preview unavailable" if preview_error else "Not read"))
                if preview_error:
                    out.append(row("Reason", preview_error))
            else:
                out.append(row("Value", "Opaque object"))
    if finished_at is not None:
        out.append(row("Returned at", format_capture_time(capture_datetime(finished_at), precise=True)))
    if preview is not None:
        rows = preview["rows"]
        summary = f"{len(rows)} {'row' if len(rows) == 1 else 'rows'}"
        if not preview["complete"]:
            summary += f" (partial) · {preview['reason']}"
        out += ["", "[bold]\\[CURSOR PREVIEW][/bold]", row("Contents", summary)]
        out += _cursor_table(preview)
    for key, title in (("cursor", "CURSOR"), ("sentCursor", "SENT CURSOR")):
        table = record.get(key)
        if table is None or (key == "sentCursor" and table == record.get("cursor")):
            continue
        out += ["", f"[bold]\\[{title}][/bold]", *_cursor_table(table)]
    for key in ("error", "exception"):
        if record.get(key):
            out += ["", row(key.capitalize(), record[key])]
    return "\n".join(out)


def provider_request(record):
    """Only reconstruct complete, supported Sender calls."""
    method = record["method"]
    args = dict(record.get("sentArguments", record["arguments"]))
    types = record.get("types", [])
    nulls = record.get("nullArguments", [])

    def require_absent_bundles():
        if any(kind == "android.os.Bundle" and index not in nulls
               for index, kind in enumerate(types)):
            raise ValueError("This call contains a Bundle that Sender cannot reconstruct completely")

    if method == "call":
        if "extras" not in args:
            bundle_indices = [i for i, kind in enumerate(types) if kind == "android.os.Bundle"]
            if not bundle_indices or not all(index in nulls for index in bundle_indices):
                raise ValueError("Bundle extras were not captured completely; create this request in Sender")
            args["extras"] = None
        uri = args.get("uri")
        if uri is None and isinstance(args.get("authority"), str):
            uri = "content://" + args["authority"]
        request = {"operation": "call", "uri": uri}
        for key in ("method", "arg", "extras"):
            if key not in args:
                raise ValueError(f"Provider {key} was not captured completely")
            request[key] = args[key]
        validate_request(request)
        return ordered_provider_request(request)
    if method in ("openFile", "openFileDescriptor", "openInputStream"):
        if method != "openInputStream" and args.get("mode") != "r":
            raise ValueError("Sender supports file reads; this captured mode cannot be reproduced")
        request = {"operation": "openFileDescriptor", "uri": args.get("uri")}
        validate_request(request)
        return ordered_provider_request(request)

    query = args.pop("queryArguments", None)
    if query is not None:
        # Captured SQL keys alone do not establish that all Bundle keys were captured.
        raise ValueError("The query Bundle was captured partially; create this request in Sender")
    if "queryArguments" in record.get("sentArguments", record["arguments"]):
        args.update(selection=None, selectionArgs=None)
        if method == "query":
            args["sortOrder"] = None
    else:
        require_absent_bundles()
    if method not in ("query", "getType", "insert", "update", "delete") or "uri" not in args:
        raise ValueError("Create this provider operation directly in Sender")
    expected = {"query": ("uri", "projection", "selection", "selectionArgs", "sortOrder"),
                "getType": ("uri",),
                "insert": ("uri", "values"), "update": ("uri", "values", "selection", "selectionArgs"),
                "delete": ("uri", "selection", "selectionArgs")}[method]
    if not args.keys() >= set(expected):
        raise ValueError("Provider arguments were not captured completely; create this request in Sender")
    request = {"operation": method, **{key: args[key] for key in expected}}
    validate_request(request)
    return ordered_provider_request(request)
