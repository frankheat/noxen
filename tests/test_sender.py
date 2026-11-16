import asyncio
import copy
import os
import sqlite3
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from noxen.db import ProjectDB
from noxen.sender import SenderError, validate_request, compare_sender_runs
from noxen.sender_service import SenderService
from noxen.sender_capture import capture_operation, prepare_intent_request, prepare_monitor_request
from noxen.frida_session import SessionConfig


class ValidationTests(unittest.TestCase):
    def test_comparison_ignores_observation_time_but_keeps_permission_changes(self):
        left = {"id": 1, "sender": {"observedAt": 10, "permissions": [{"name": "test", "granted": True}]}}
        right = copy.deepcopy(left)
        right["id"] = 2
        right["sender"]["observedAt"] = 20
        self.assertEqual(compare_sender_runs(left, right)["diff"], "")
        right["sender"]["permissions"][0]["granted"] = False
        self.assertIn('"granted"', compare_sender_runs(left, right)["diff"])

    def test_nested_values_are_lossless_and_input_is_not_mutated(self):
        raw = {"operation": "sendBroadcast", "intent": {"component": "test.app/.Receiver", "extras": {
            "n": {"type": "long", "value": "9223372036854775807"},
            "bundle": {"type": "Bundle", "value": {"next": {"type": "Intent", "value": {"action": ""}}}},
            "null": {"type": "String", "value": None},
        }}}
        before = copy.deepcopy(raw)
        valid = validate_request(raw)
        self.assertEqual(before, raw)
        self.assertEqual(valid["intent"]["component"], "test.app/test.app.Receiver")
        self.assertEqual(valid["intent"]["extras"], raw["intent"]["extras"])

    def test_ambiguous_or_unsupported_requests_are_rejected(self):
        for request in (
            {"operation": "startActivity", "intent": {}},
            {"operation": "sendBroadcast", "intent": {"package": "a", "selector": {}}},
            {"operation": "sendBroadcast", "intent": {"extras": {"x": {"type": "Parcelable", "value": "opaque"}}}},
            {"operation": "query", "uri": "file:///tmp/a"},
            {"operation": "query", "uri": "content://test", "maxRows": True},
            {"operation": "delete", "uri": "content://test", "maxRows": 10},
            {"operation": "sendBroadcast", "intent": {}, "unexpected": True},
            {"operation": "sendBroadcast", "intent": {"extras": {"huge": {"type": "double", "value": 10 ** 400}}}},
        ):
            with self.subTest(request=request), self.assertRaises(SenderError):
                validate_request(request)

    def test_limits_and_long_precision(self):
        for value in (1, "9223372036854775808", " 1", "1.0", "01"):
            with self.subTest(value=value), self.assertRaises(SenderError):
                validate_request({"operation": "sendBroadcast", "intent": {"extras": {"x": {"type": "long", "value": value}}}})
        self.assertEqual(validate_request({"operation": "query", "uri": "content://a"})["maxRows"], 100)


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "s.noxen")
        self.db = ProjectDB(self.path)
        self.db.create("test")
        self.service = SenderService(self.db)
        self.started, self.release = threading.Event(), threading.Event()
        self.calls = 0

        def execute(request, job_id):
            self.calls += 1
            self.started.set()
            self.release.wait(5)
            return {"state": "returned", "result": {"kind": "void"}}

        self.endpoint = SimpleNamespace(device_id="emulator", is_ready=lambda: True,
            connect=lambda package: {"package": package, "pid": 1, "uid": 10001},
            close=lambda: None, execute=execute)
        await self.service.connect(self.endpoint, "test.app", self.service.token)
        self.request = self.service.save_request("test", {"operation": "sendBroadcast", "intent": {}})

    async def asyncTearDown(self):
        self.release.set()
        if self.service.task:
            await self.service.task
        self.db.close()
        self.tmp.cleanup()

    def execute(self, key="one"):
        return self.service.execute(self.request["id"], self.request["revision"], self.service.token, key)

    async def test_idempotency_revision_and_one_inflight(self):
        run = self.execute()
        self.assertEqual(self.execute()["id"], run["id"])
        with self.assertRaises(SenderError):
            self.execute("two")
        self.release.set()
        result = await self.service.wait(run["id"])
        self.assertEqual(result["state"], "returned")
        self.assertEqual(self.calls, 1)
        updated = self.service.save_request("updated", self.request["request"], self.request["id"], 1)
        with self.assertRaises(SenderError):
            self.execute("three")
        self.assertEqual(self.service.get_run(run["id"])["name"], "test")
        self.db.remove_sender_request(updated["id"], updated["revision"])
        self.assertEqual(self.service.get_run(run["id"])["request"], self.request["request"])

    async def test_failed_initial_save_never_invokes_android(self):
        with patch.object(self.db, "create_sender_run", side_effect=sqlite3.OperationalError("disk full")):
            with self.assertRaises(sqlite3.OperationalError):
                self.execute()
        self.assertEqual(self.calls, 0)
        self.assertIsNone(self.service.active_run)

    async def test_disconnect_preserves_unknown_and_rejects_late_result(self):
        run = self.execute()
        await asyncio.to_thread(self.started.wait, 2)
        await self.service.disconnect(self.service.token)
        self.release.set()
        await self.service.task
        self.assertEqual(self.service.get_run(run["id"])["state"], "unknown")
        self.assertEqual(self.calls, 1)

    async def test_result_save_failure_is_recoverable(self):
        with patch.object(self.db, "save_sender_run", side_effect=sqlite3.OperationalError("disk full")):
            run = self.execute()
            self.release.set()
            await self.service.task
        self.assertEqual(self.service.get_run(run["id"])["state"], "returned")
        self.assertIn(run["id"], self.service.unsaved)
        self.service.retry_save()
        self.assertFalse(self.service.unsaved)
        self.assertEqual(self.db.sender_run(run_id=run["id"])["state"], "returned")

    async def test_wait_timeout_does_not_cancel_or_repeat(self):
        run = self.execute()
        result = await self.service.wait(run["id"], timeout=0.01)
        self.assertEqual(result["state"], "preparing")
        self.release.set()
        self.assertEqual((await self.service.wait(run["id"]))["state"], "returned")
        self.assertEqual(self.calls, 1)

    async def test_cancellation_request_does_not_claim_that_android_stopped(self):
        self.request = self.service.save_request("Query", {"operation": "query", "uri": "content://test/notes"})
        self.endpoint.cancel = lambda job_id: True
        run = self.execute()
        result = await self.service.cancel(run["id"], self.service.token)
        self.assertTrue(result["cancellationRequested"])
        self.assertNotEqual(result["state"], "cancelled")
        self.release.set()
        result = await self.service.wait(run["id"])
        self.assertEqual(result["state"], "returned")
        self.assertTrue(result["cancellationRequested"])

    async def test_reopen_marks_unfinished_unknown_without_replay(self):
        self.db.create_sender_run("interrupted", {"state": "preparing", "request": {}})
        SenderService(self.db)
        self.assertEqual(self.db.sender_run(execution_key="interrupted")["state"], "unknown")
        self.assertEqual(self.calls, 0)

    async def test_conflicting_updates_do_not_overwrite(self):
        self.service.save_request("changed", self.request["request"], self.request["id"], 1)
        with self.assertRaises(ValueError):
            self.service.save_request("stale", self.request["request"], self.request["id"], 1)
        self.assertEqual(self.service.get_request(self.request["id"])["name"], "changed")

    async def test_sender_crash_is_distinct_and_does_not_claim_causality(self):
        run = self.execute()
        await asyncio.to_thread(self.started.wait, 2)
        crash = SimpleNamespace(pid=1, report="test report", process_name="test.app", summary="test crash")
        self.service._detached(self.endpoint, self.service.token, "test.app", "process-terminated", crash)
        self.release.set()
        await self.service.task
        stored = self.service.get_run(run["id"])
        self.assertEqual(stored["state"], "unknown")
        self.assertEqual(self.db.get_crash(stored["senderCrashId"])["role"], "sender")

    async def test_database_summary_search_reaches_older_runs_without_returning_payloads(self):
        for index in range(205):
            self.db.create_sender_run(str(index), {"name": f"run {index}", "state": "returned",
                "sender": {"package": "test.app"}, "createdAt": "time", "request": {"marker": "needle" if index == 0 else "other"}})
        rows = self.db.sender_run_summaries(query="needle")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "run 0")
        self.assertNotIn("request", rows[0])

    async def test_disconnect_before_dispatch_does_not_start_android_call(self):
        run = self.execute()
        await self.service.disconnect(self.service.token)
        await self.service.task
        self.assertEqual(self.calls, 0)
        self.assertEqual(self.service.get_run(run["id"])["state"], "unknown")

    async def test_observer_conflicts_are_rejected_before_spawn_or_cleanup(self):
        self.endpoint.pid = 1
        self.endpoint.observer = None
        for device, config in (("other", SessionConfig(spawn_package="other.app")),
                               ("emulator", SessionConfig(spawn_package="test.app")),
                               ("emulator", SessionConfig(attach_pid=1))):
            with self.subTest(device=device, config=config), self.assertRaises(SenderError):
                self.service.validate_observer_config(device, config)
        self.service.validate_observer_config("emulator", SessionConfig(attach_pid=2))
        self.endpoint.observer = object()
        with self.assertRaises(SenderError):
            self.service.validate_observer_config("emulator", SessionConfig(attach_pid=2))

    async def test_dispatch_records_current_identity_and_ignores_stale_start(self):
        run = self.execute()
        identity = {"package": "test.app", "uid": 10001, "pid": 1, "permissions": [{"name": "test.permission", "granted": False}]}
        self.service._started(self.service.token, run["id"], "wrong-key", 10, identity)
        self.assertEqual(self.service.get_run(run["id"])["state"], "preparing")
        self.service._started(self.service.token, run["id"], "one", 20, identity)
        self.assertEqual(self.service.get_run(run["id"])["sender"], identity)


class CaptureTests(unittest.TestCase):
    def test_hook_method_implies_the_sending_operation_only_when_unambiguous(self):
        for method, operation in (("sendOrderedBroadcast", "sendOrderedBroadcast"), ("onReceive", "sendBroadcast"),
                                  ("getIntent", "startActivity"), ("getService", "startService"),
                                  ("bindService", None), ("setResult", None), ("custom", None)):
            self.assertEqual(capture_operation({"method": method}), operation, method)

    def test_monitor_provider_calls_become_requests_only_when_fully_captured(self):
        uri = {"type": "android.net.Uri", "value": "content://test/notes"}
        text = lambda value: {"type": "java.lang.String", "value": value}
        strings = lambda *items: {"type": "[Ljava.lang.String;", "count": len(items),
                                  "items": [{"type": "java.lang.String", "value": item} for item in items]}
        U, S, A, B, V = ("android.net.Uri", "java.lang.String", "[Ljava.lang.String;", "android.os.Bundle",
                         "android.content.ContentValues")
        resolver, transport = "android.content.ContentResolver", "android.content.ContentProvider$Transport"
        source = "android.content.AttributionSource"
        def event(clazz, method, types, *arguments):
            return {"class": clazz, "method": method, "types": types, "arguments": list(arguments)}

        legacy = event(resolver, "query", [U, A, S, A, S], uri, strings("_id", "title"), text("a = ?"),
                       strings("1"), text(None))
        self.assertEqual(validate_request(prepare_monitor_request(legacy)), {
            "operation": "query", "uri": "content://test/notes", "projection": ["_id", "title"],
            "selection": "a = ?", "selectionArgs": ["1"], "sortOrder": None, "maxRows": 100, "maxBytes": 262144})
        inbound = event(transport, "query", [source, U, A, B, "android.os.ICancellationSignal"],
                        {"type": source, "value": "caller.app"}, uri, {"type": A, "value": None},
                        {"type": B, "queryArguments": {"selection": text("x"), "selectionArgs": {"type": A, "value": None},
                                                      "sortOrder": text("title")}}, {"type": "x", "opaque": True})
        self.assertEqual(prepare_monitor_request(inbound), {
            "operation": "query", "uri": "content://test/notes", "projection": None,
            "selection": "x", "selectionArgs": None, "sortOrder": "title"})
        call = event(transport, "call", [source, S, S, S, B], {"type": source, "value": "caller.app"},
                     text("test"), text("ping"), text(None), {"type": B, "value": None})
        self.assertEqual(validate_request(prepare_monitor_request(call)),
                         {"operation": "call", "uri": "content://test", "method": "ping", "arg": None})
        self.assertEqual(prepare_monitor_request(event(resolver, "openInputStream", [U], uri)),
                         {"operation": "openFileDescriptor", "uri": "content://test/notes"})
        self.assertEqual(prepare_monitor_request(event(resolver, "delete", [U, S, A], uri, text(None), {"type": A, "value": None})),
                         {"operation": "delete", "uri": "content://test/notes", "selection": None, "selectionArgs": None})

        partial = strings("_id")
        partial["count"] = 40  # Only the first values were captured.
        for refused in (
            event(resolver, "query", [U, A, S, A, S], uri, partial, text(None), strings(), text(None)),
            event(resolver, "query", [U, A, S, A, S], dict(uri, truncated=True), strings(), text(None), strings(), text(None)),
            event(resolver, "insert", [U, V], uri, {"type": V, "opaque": True}),
            event(transport, "call", [source, S, S, S, B], {"type": source, "value": "c"}, text("test"), text("m"),
                  text(None), {"type": B, "opaque": True}),
            event(resolver, "openOutputStream", [U], uri),
            event("android.util.Log", "d", [S, S], text("tag"), text("message")),
            {"class": resolver, "method": "query", "types": [U]},
        ):
            with self.assertRaises(SenderError, msg=refused):
                prepare_monitor_request(refused)

    def test_missing_extras_bundle_stays_distinct_from_an_empty_bundle(self):
        entry = self.capture()
        self.assertEqual(prepare_intent_request(entry, "sendBroadcast")["intent"]["extras"], {})
        entry["intent"].pop("extrasMeta")
        request = prepare_intent_request(entry, "sendBroadcast")
        self.assertIsNone(request["intent"]["extras"])
        validate_request(request)

    def capture(self):
        return {"intent": {"component": "test.app/.Receiver", "action": "", "data": None, "mimeType": None,
                           "package": None, "flags": -2147483648, "categories": [], "selector": None,
                           "clipData": None, "extras": {}, "extrasMeta": {"omitted": 0}}}

    def test_complete_capture_preserves_flags_empty_and_null(self):
        entry = self.capture()
        original = copy.deepcopy(entry)
        request = prepare_intent_request(entry, "sendBroadcast")
        self.assertEqual(request["intent"]["flags"], 0x80000000)
        self.assertEqual(request["intent"]["action"], "")
        self.assertIsNone(request["intent"]["data"])
        self.assertEqual(entry, original)
        validate_request(request)

    def test_unknown_or_incomplete_fields_cannot_be_replayed_as_empty(self):
        for change in (lambda i: i.pop("selector"),
                       lambda i: i.update(extrasMeta={"omitted": 1}),
                       lambda i: i.update(action="x" * 2048),
                       lambda i: i.update(extras={"opaque": {"structuredVersion": 1,
                           "structured": {"kind": "object", "type": "test.Private"}}})):
            entry = self.capture()
            change(entry["intent"])
            with self.assertRaises(SenderError):
                prepare_intent_request(entry, "sendBroadcast")
