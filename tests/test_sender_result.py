import copy
import io
import unittest

from rich.console import Console

from noxen.sender import INTENT_OPERATIONS, PROVIDER_OPERATIONS, render_sender_detail


def render(operation, result=None, *, width=100, revision=None, view="summary", **fields):
    run = {
        "id": 24, "revision": 1, "request": {"operation": operation}, "name": "Example", "state": "returned",
        "sender": {"package": "dev.example.notes", "uid": 10116, "pid": 31498}, "device": "emulator",
        "createdAt": "host time", **fields,
    }
    if result is not None:
        run["result"] = result
    before = copy.deepcopy(run)
    buffer = io.StringIO()
    Console(file=buffer, width=width).print(render_sender_detail(run, revision, view=view))
    assert before == run
    return buffer.getvalue()


class SenderResultTests(unittest.TestCase):
    def test_summary_matches_every_operation_without_rendering_raw_data_by_default(self):
        cases = [
            ("startActivity", {"kind": "void"}, "Activity launch unverified"),
            ("sendBroadcast", {"kind": "void"}, "Delivery unverified"),
            ("sendOrderedBroadcast", {"kind": "broadcastResult", "code": 1, "data": "Done", "extras": None},
             "Final callback received"),
            ("startService", {"kind": "component", "value": "dev.test/.Service"}, "Component returned"),
            ("startForegroundService", {"kind": "component", "value": None}, "No component returned"),
            ("stopService", {"kind": "boolean", "value": False}, "No matching running service"),
            ("query", {"kind": "cursor", "columns": ["title"], "rows": []}, "0 rows captured"),
            ("getType", {"kind": "String", "value": "text/plain"}, "MIME type"),
            ("insert", {"kind": "uri", "value": "content://dev.test/item/1"}, "Returned URI"),
            ("update", {"kind": "int", "value": 0}, "Rows updated"),
            ("delete", {"kind": "int", "value": 2}, "Rows deleted"),
            ("call", {"kind": "Bundle", "value": {"values": {}}}, "Empty Bundle"),
            ("openFileDescriptor", {"kind": "file", "encoding": "base64", "value": "aGVsbG8K", "bytes": 6},
             "Bytes captured"),
        ]
        self.assertEqual({case[0] for case in cases}, set(INTENT_OPERATIONS + PROVIDER_OPERATIONS))
        for operation, result, expected in cases:
            with self.subTest(operation=operation):
                summary = render(operation, result)
                self.assertIn(expected, summary)
                self.assertNotIn("[RAW RESULT]", summary)
                self.assertNotIn("[TIMING]", summary)
                self.assertIn("[RAW RESULT]", render(operation, result, view="raw"))

    def test_cursor_distinguishes_null_empty_omissions_and_limits(self):
        self.assertIn("No cursor returned", render("query", {"kind": "cursor", "value": None}))
        self.assertIn("Result not captured", render("query", {"kind": "cursor", "rows": [], "truncated": True,
                                                             "reason": "Column names exceed the byte limit"}))
        result = {"kind": "cursor", "columns": ["id", "payload"], "rows": [
            [{"type": "long", "value": "9007199254740993"}, {"type": "blob", "captured": False}],
        ], "truncated": False}
        summary = render("query", result)
        for value in ("1 row captured · Partial result", "Cells not captured", "payload", "9007199254740993", "BLOB"):
            self.assertIn(value, summary)
        result["rows"] *= 50
        self.assertIn("Preview: 40/50 rows", render("query", result))
        result["columns"].extend(f"extra{n}" for n in range(12))
        self.assertIn("1/14 columns", render("query", result, width=25).replace("\n", " "))

    def test_partial_bundle_and_file_payloads_remain_inspectable(self):
        leaf = {"type": "java.lang.String", "value": "[literal]", "truncated": True}
        nested = {"type": "android.os.Bundle", "value": {"values": {"message": leaf}}}
        bundle = {"values": {"details": nested}}
        summary = render("call", {"kind": "Bundle", "value": bundle})
        self.assertIn("Partial capture", summary)
        self.assertIn("[literal]", summary)
        result = {"kind": "file", "encoding": "base64", "value": "aGVsbG8K", "bytes": 6, "truncated": True}
        self.assertIn("Partial capture", render("openFileDescriptor", result))
        self.assertNotIn(result["value"], render("openFileDescriptor", result))
        self.assertIn(result["value"], render("openFileDescriptor", result, view="raw"))
        self.assertIn("No MIME type returned", render("getType", {"kind": "String", "value": None}))
        self.assertIn("No URI returned", render("insert", {"kind": "uri", "value": None}))

    def test_statuses_report_evidence_and_keep_timing_in_details(self):
        summary = render("sendBroadcast", state="unknown", error="Sender detached", senderCrashId=12)
        self.assertIn("Outcome unknown", summary)
        self.assertIn("Sender crash : #12", summary)
        self.assertNotIn("Delivery unverified", summary)
        defaults = render("sendOrderedBroadcast", {"kind": "broadcastResult", "code": 0, "data": None, "extras": None})
        self.assertIn("Result matches the initial values", defaults)
        self.assertIn("Receiver delivery unverified", defaults)
        self.assertIn("Cancellation requested", render("query", state="cancelled", cancellationRequested=True))
        self.assertIn("See Details", render("update", {"kind": "int", "value": 2}, revision=2))
        details = render("update", {"kind": "int", "value": 2}, revision=2, view="details")
        for text in ("[TIMING]", "[SENDER]", "[REQUEST]", "request has changed"):
            self.assertIn(text, details)
