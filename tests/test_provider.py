import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from textual.widgets import RichLog, Switch, TabbedContent, TextArea

from noxen.app import NoxenApp
from noxen.db import ProjectDB
from noxen.frida_session import SessionConfig
from noxen.provider_service import ProviderService
from noxen.sender_json_editor import JsonRequestEditor
from noxen.providers import provider_as_json, provider_entry, provider_request, render_provider
from noxen.rendering import entry_to_filter_context
from noxen.settings import load_settings
from noxen.provider_fields import ordered_provider_arguments
from noxen.sender import validate_request
from noxen.sender_json import format_request
from tests.ui_test_case import IsolatedAppTestCase


def request(id_="provider-1"):
    return {"noxenEvent": "provider_request", "id": id_, "decisionId": id_,
            "state": "held", "direction": "outgoing", "class": "android.content.ContentResolver",
            "method": "query", "arguments": {"uri": "content://demo/notes", "selection": None},
            "time": 10, "captureSequence": 1}


class ProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_complete_query_bundle_can_be_repeated_with_edited_selection(self):
        record = dict(request(), arguments={
            "uri": "content://demo/notes", "projection": None,
            "queryArguments": {"selection": "title = ?", "selectionArgs": ["second"], "sortOrder": None},
        }, queryArgumentsComplete=True)
        converted = provider_request(record)
        self.assertEqual(converted["selectionArgs"], ["second"])
        self.assertEqual(converted["operation"], "query")
        record["sentArguments"] = {**record["arguments"], "queryArguments": {
            "selection": "_id = ?", "selectionArgs": ["2"], "sortOrder": "_id ASC",
        }}
        self.assertEqual(provider_request(record)["selection"], "_id = ?")
        self.assertEqual(provider_request(record)["selectionArgs"], ["2"])
        record.pop("queryArgumentsComplete")
        with self.assertRaises(ValueError):
            provider_request(record)

    async def test_complete_cursor_detail_is_identical_for_previews_and_held_snapshots(self):
        table = {"columns": ["title"], "rows": [[{"type": "string", "value": "first"}]]}
        record = dict(request(), state="returned", result={"type": "android.database.Cursor"})
        snapshot = dict(provider_entry(dict(record, cursor=table), "test"), id=1)
        preview = dict(provider_entry(dict(record, cursorPreview=dict(table, complete=True)), "test"), id=1)
        snapshot_section = render_provider(snapshot).split("[CURSOR]", 1)[1]
        self.assertEqual(snapshot_section, render_provider(preview).split("[CURSOR]", 1)[1])
        self.assertIn("Contents", snapshot_section)
        self.assertIn("1 row", snapshot_section)
        self.assertIn("1 row\n\n", snapshot_section)

    async def test_provider_order_matches_details_json_editor_and_sender(self):
        arguments = {
            "values": {"title": {"value": "updated", "type": "String"},
                       "body": {"type": "String", "value": "demo"}},
            "selectionArgs": ["1"], "uri": "content://demo/notes", "selection": "_id = ?",
        }
        record = dict(request(), method="update", arguments=arguments)
        expected = ["uri", "selection", "selectionArgs", "values"]
        self.assertEqual(list(ordered_provider_arguments(arguments)), expected)
        entry = dict(provider_entry(record, "test"), id=1)
        view = provider_as_json(entry)
        self.assertEqual([key for key in view if key in expected], expected)
        request_view = provider_request(record)
        for value in (request_view, validate_request(request_view),
                      json.loads(format_request(dict(reversed(list(request_view.items())))))):
            self.assertEqual([key for key in value if key in expected], expected)
            self.assertEqual(list(value["values"]), ["body", "title"])
            self.assertEqual(list(value["values"]["title"]), ["type", "value"])
        detail = render_provider(entry)
        positions = [detail.index("  " + key + " ") for key in expected]
        self.assertEqual(positions, sorted(positions))
        self.assertLess(detail.index("selectionArgs"), detail.index("Key"))
        self.assertEqual(arguments["values"]["title"], {"value": "updated", "type": "String"})

    async def test_content_values_use_a_table_in_both_request_sections(self):
        record = dict(request(), method="insert", arguments={
            "uri": "content://demo/notes",
            "values": {"title": {"type": "String", "value": "first"},
                       "size": {"type": "long", "value": "9223372036854775807"},
                       "optional": {"type": "String", "value": None}},
        })
        record["sentArguments"] = {
            "uri": record["arguments"]["uri"],
            "values": {"title": {"type": "String", "value": "changed"}},
        }
        detail = render_provider(dict(provider_entry(record, "test"), id=1))
        self.assertEqual(detail.count("ContentValues ("), 2)
        self.assertIn('"changed"', detail)
        self.assertIn('"first"', detail)
        self.assertIn("9223372036854775807", detail)
        self.assertIn("null", detail)
        self.assertNotIn('"type":', detail)

    async def test_sender_provider_conversion_preserves_supported_operations(self):
        uri = "content://demo/notes"
        cases = [
            ("query", {"uri": uri, "projection": None, "selection": None,
                       "selectionArgs": None, "sortOrder": None}, "query"),
            ("insert", {"uri": uri, "values": {"title": {"type": "String", "value": "first"}}}, "insert"),
            ("update", {"uri": uri, "values": {}, "selection": None, "selectionArgs": None}, "update"),
            ("delete", {"uri": uri, "selection": None, "selectionArgs": None}, "delete"),
            ("call", {"authority": "demo", "method": "echo", "arg": None, "extras": None}, "call"),
            ("openFileDescriptor", {"uri": uri, "mode": "r"}, "openFileDescriptor"),
            ("openFile", {"uri": uri, "mode": "r"}, "openFileDescriptor"),
            ("openInputStream", {"uri": uri}, "openFileDescriptor"),
        ]
        for method, arguments, operation in cases:
            with self.subTest(method=method):
                record = dict(request(), method=method, arguments=arguments)
                converted = provider_request(record)
                self.assertEqual(converted["operation"], operation)
                self.assertEqual(converted["uri"], "content://demo" if method == "call" else uri)
        record = dict(request(), method="call", arguments={"uri": uri, "method": "echo", "arg": None},
                      types=["android.net.Uri", "java.lang.String", "java.lang.String", "android.os.Bundle"],
                      nullArguments=[3])
        self.assertIsNone(provider_request(record)["extras"])
        record["nullArguments"] = []
        with self.assertRaises(ValueError):
            provider_request(record)
        with self.assertRaises(ValueError):
            provider_request(dict(request(), method="openFileDescriptor", arguments={"uri": uri, "mode": "rw"}))
        with self.assertRaises(ValueError):
            provider_request(dict(request(), arguments={"uri": uri, "projection": None,
                             "queryArguments": {"selection": None, "selectionArgs": None, "sortOrder": None}}))

    async def test_get_type_capture_can_be_sent_with_its_effective_uri(self):
        record = dict(request(), method="getType", arguments={"uri": "content://demo/notes"})
        self.assertEqual(provider_request(record), {"operation": "getType", "uri": "content://demo/notes"})
        record["sentArguments"] = {"uri": "content://demo/changed"}
        self.assertEqual(provider_request(record), {"operation": "getType", "uri": "content://demo/changed"})
        view = provider_as_json(provider_entry(record, "connection"))
        self.assertEqual(view["operation"], "getType")
        self.assertEqual(view["uri"], "content://demo/changed")
        record["sentArguments"] = {}
        with self.assertRaises(ValueError):
            provider_request(record)

    async def test_json_detail_formats_reconstructible_and_partial_provider_captures(self):
        arguments = {"uri": "content://demo/notes", "projection": ["title"],
                     "selection": None, "selectionArgs": None, "sortOrder": None}
        cursor = {"columns": ["title"], "rows": [[{"type": "string", "value": "first"}]]}
        record = dict(request(), state="returned", arguments=arguments,
                      result={"type": "android.database.Cursor", "opaque": True}, cursor=cursor,
                      sentCursor=cursor, finishedAt=30)
        ui = SimpleNamespace(_detail_json=True, theme="noxen-dark")
        entry = provider_entry(record, "internal-token")
        view = json.loads(NoxenApp._entry_renderable(ui, entry).plain)
        self.assertEqual(list(view)[:3], ["hook", "operation", "uri"])
        self.assertEqual(view["hook"], "android.content.ContentResolver.query()")
        self.assertEqual(view["operation"], "query")
        self.assertEqual(view["response"]["cursor"], cursor)
        self.assertNotIn("opaque", view["response"])
        self.assertNotIn("notCaptured", view)
        self.assertNotIn("sentCursor", view["response"])
        self.assertNotIn("returnedAt", view["response"])
        self.assertNotIn("direction", view)
        detail = render_provider(dict(entry, id=1))
        self.assertIn("Direction", detail)
        self.assertIn("outgoing", detail)
        self.assertIn("Returned at", detail.split("[RESPONSE]", 1)[1].split("[CURSOR]", 1)[0])
        self.assertTrue({"noxenEvent", "connection", "decisionId"}.isdisjoint(view))

        record["arguments"] = {"uri": arguments["uri"]}
        record["opaqueArguments"] = [{"index": 1, "type": "android.os.Bundle"}]
        record.pop("cursor")
        record.pop("sentCursor")
        entry = provider_entry(record, "internal-token")
        view = json.loads(NoxenApp._entry_renderable(ui, entry).plain)
        self.assertNotIn("operation", view)
        self.assertEqual(view["arguments"], record["arguments"])
        self.assertEqual(view["response"], {"type": "android.database.Cursor"})
        self.assertEqual(view["notCaptured"], ["Argument 2 (android.os.Bundle)", "Cursor rows not read"])

    async def test_query_detail_distinguishes_unread_and_partial_results(self):
        record = dict(request(), state="returned", phase="request", decision="forwarded",
                      result={"type": "android.content.ContentResolver$CursorWrapperInner", "opaque": True})
        entry = dict(provider_entry(record, "connection"), id=1)
        detail = render_provider(entry)
        self.assertIn("Contents", detail)
        self.assertIn("Not read", detail)
        self.assertNotIn("Opaque object", detail)
        self.assertNotIn("Phase", detail)

        record.update(state="held", phase="response")
        held_detail = render_provider(dict(provider_entry(record, "connection"), id=1))
        self.assertIn("Phase", held_detail)
        self.assertIn("Not read", held_detail)
        self.assertNotIn("Next", held_detail)
        ui = SimpleNamespace(_detail_json=True, theme="noxen-dark")
        held_json = json.loads(NoxenApp._entry_renderable(ui, provider_entry(record, "connection")).plain)
        self.assertNotIn("phase", held_json)
        self.assertEqual(held_json["response"]["type"], record["result"]["type"])
        self.assertIn("Cursor rows not read", held_json["notCaptured"])

        record.update(state="returned", cursorPreview={
            "columns": ["title"], "rows": [[{"type": "string", "value": "first"}]],
            "complete": False, "reason": "Row limit reached",
        })
        preview_detail = render_provider(dict(provider_entry(record, "connection"), id=1))
        self.assertIn("1 row (partial)", preview_detail)
        self.assertIn('"first"', preview_detail)

    async def test_history_filter_uses_the_forwarded_provider_uri(self):
        record = request()
        record["sentArguments"] = {"uri": "content://demo/changed", "selection": None}
        self.assertEqual(entry_to_filter_context(provider_entry(record, "connection"))["data"],
                         "content://demo/changed")

    async def test_cursor_response_updates_one_history_entry_and_survives_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = ProjectDB(str(Path(tmp) / "provider.noxen"))
            db.create("provider")
            service = ProviderService(db)
            session = SimpleNamespace(_config=SimpleNamespace(target_label=lambda: "demo"),
                                      is_ready=lambda: True)
            service.bind(session)
            session.provider_cb(request())
            service.drain()
            original = {"columns": ["_display_name", "_size"],
                        "rows": [[{"type": "string", "value": "report.txt"},
                                  {"type": "integer", "value": "18"}]]}
            changed = {"columns": original["columns"],
                       "rows": [[{"type": "string", "value": "../files/provider-proof.txt"},
                                 {"type": "integer", "value": "18"}]]}
            session.provider_cb({"noxenEvent": "provider_update", "id": "provider-1",
                                 "phase": "request", "state": "forwarded", "releasedAt": 11})
            session.provider_cb({"noxenEvent": "provider_response", "id": "provider-1",
                                 "phase": "response", "state": "held", "time": 20,
                                 "decisionId": "provider-1:response", "cursor": original})
            service.drain()
            self.assertEqual(service.status()["held"]["decisionId"], "provider-1:response")
            session.provider_cb({"noxenEvent": "provider_update", "id": "provider-1",
                                 "phase": "response", "state": "modified_forwarded", "sentCursor": changed})
            session.provider_cb({"noxenEvent": "provider_result", "id": "provider-1",
                                 "state": "returned", "time": 30,
                                 "result": {"type": "android.database.Cursor", "opaque": True}})
            service.drain()
            [entry] = db._load_all()
            self.assertEqual(entry["provider"]["cursor"], original)
            self.assertEqual(entry["provider"]["sentCursor"], changed)
            self.assertEqual(entry["outcome"], "modified_forwarded")
            self.assertEqual(entry["provider"]["time"], 10)
            self.assertEqual(entry["provider"]["responseAt"], 20)
            self.assertEqual(entry["provider"]["finishedAt"], 30)
            db.close()
            reopened = ProjectDB(str(Path(tmp) / "provider.noxen"))
            [restored] = reopened.open_existing()
            self.assertEqual(restored["provider"]["sentCursor"], changed)
            detail = render_provider(restored)
            self.assertIn("[SENT CURSOR]", detail)
            self.assertIn("_display_name  ", detail)
            self.assertIn('"report.txt"  ', detail)
            self.assertNotIn('"columns":', detail)
            legacy = dict(restored, provider=dict(restored["provider"], sentCursor=original))
            self.assertIn("[CURSOR]", render_provider(legacy))
            self.assertNotIn("[SENT CURSOR]", render_provider(legacy))
            reopened.clear_intents()
            self.assertEqual(reopened._load_all(), [])
            self.assertEqual(reopened.provider_calls(), [])
            reopened.close()

    async def test_persist_decision_result_reopen_and_reject_stale_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = ProjectDB(str(Path(tmp) / "provider.noxen"))
            db.create("provider")
            service = ProviderService(db)
            calls = []
            rpc = SimpleNamespace(resolve_provider=lambda *args: calls.append(args) or True)
            session = SimpleNamespace(_config=SimpleNamespace(target_label=lambda: "demo"),
                                      _script=SimpleNamespace(exports_sync=rpc), is_ready=lambda: True)
            service.bind(session)
            session.provider_cb(request())
            self.assertEqual(service.status()["held"]["arguments"]["selection"], None)
            with self.assertRaises(ValueError):
                await service.resolve("old", "provider-1", "drop")
            self.assertEqual(calls, [])
            await service.resolve(service.connection, "provider-1", "forward",
                                  {"uri": "content://demo/notes", "selection": "x"})
            session.provider_cb({"noxenEvent": "provider_update", "id": "provider-1", "state": "modified_forwarded",
                                 "sentArguments": {"uri": "content://demo/notes", "selection": "x"}})
            session.provider_cb({"noxenEvent": "provider_result", "id": "provider-1", "state": "returned",
                                 "time": 30, "captureSequence": 2, "result": {"type": "int", "value": 1}})
            service.drain()
            self.assertIsNone(service.held)
            [stored] = db.provider_calls()
            self.assertEqual((stored["time"], stored["finishedAt"]), (10, 30))
            self.assertIsNone(stored["arguments"]["selection"])
            self.assertEqual(stored["sentArguments"]["selection"], "x")
            self.assertEqual(stored["decision"], "modified_forwarded")
            db.close()
            db.open_existing()
            self.assertEqual(db.provider_calls()[0]["state"], "returned")
            db.close()

    async def test_failed_edit_keeps_hold_and_stale_connection_cannot_replace_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = ProjectDB(str(Path(tmp) / "provider.noxen"))
            db.create("provider")
            service = ProviderService(db)
            session = SimpleNamespace(_config=SimpleNamespace(target_label=lambda: "demo"), is_ready=lambda: True)
            service.bind(session)
            session.provider_cb(request())
            session.provider_cb({"noxenEvent": "provider_edit_error", "id": "provider-1", "state": "held", "error": "Bad value"})
            self.assertEqual(service.status()["held"]["error"], "Bad value")
            service.bind(None)
            self.assertEqual(db.provider_calls()[0]["state"], "unknown")
            session.provider_cb(request("stale"))
            service.drain()
            self.assertIsNone(service.held)
            self.assertEqual(len(db.provider_calls()), 1)
            db.close()


class ProviderUITests(IsolatedAppTestCase):
    async def test_get_type_response_can_be_edited_without_read_cursor(self):
        app = NoxenApp(SimpleNamespace(project=None, new_project=str(self.settings_path.parent / "mime-response"),
                                       skip_device_scan=True))
        async with app.run_test(size=(140, 48)):
            service = app.provider_service
            session = SimpleNamespace(_config=SimpleNamespace(target_label=lambda: "demo"), is_ready=lambda: True)
            service.bind(session)
            app.frida_session = session
            app._connection_state = "connected"
            app._intercept_mode = True
            service.receive(service.connection, dict(request(), method="getType"))
            service.receive(service.connection, {
                "noxenEvent": "provider_response", "id": "provider-1", "state": "held",
                "phase": "response", "decisionId": "provider-1:response",
                "result": {"type": "java.lang.String", "value": "text/plain"},
                "editableResult": {"value": "text/plain"},
            })
            app._provider_tick()
            self.assertFalse(app.query_one("#btn_read_cursor").display)
            self.assertFalse(app.query_one("#btn_edit").disabled)
            app._enter_edit_mode()
            area = app.query_one("#edit_form", JsonRequestEditor).area
            self.assertEqual(area.root, "providerResponse")
            self.assertEqual(area.operation, "getType")
            self.assertEqual(json.loads(area.text),
                             {"value": "text/plain"})
            service.receive(service.connection, {
                "noxenEvent": "provider_update", "id": "provider-1", "state": "modified_forwarded",
                "phase": "response", "sentResult": {"type": "java.lang.String", "value": None},
            })
            service.receive(service.connection, {
                "noxenEvent": "provider_result", "id": "provider-1", "state": "returned", "time": 30,
                "result": {"type": "java.lang.String", "value": "text/plain"},
            })
            app._provider_tick()
            entry = app.db._load_all()[0]
            self.assertEqual(entry["outcome"], "modified_forwarded")
            self.assertIn('Sent value', render_provider(entry))
            self.assertIsNone(json.loads(NoxenApp._entry_renderable(
                SimpleNamespace(_detail_json=True, theme="noxen-dark"), entry).plain)["response"]["sentValue"])
            app.frida_session = None
            service.bind(None)

    async def test_saving_cursor_preview_setting_updates_the_connected_agent(self):
        app = NoxenApp(SimpleNamespace(project=None, new_project=str(self.settings_path.parent / "preview-settings"),
                                       skip_device_scan=True))
        async with app.run_test(size=(120, 40)) as pilot:
            app._init_session(SessionConfig(attach_pid=1))
            session = app.frida_session
            values = []
            script = SimpleNamespace(exports_sync=SimpleNamespace(
                set_cursor_previews=lambda value: values.append(value) or True,
            ))
            session._script = session._provider_script = script
            session._ready = True
            try:
                await pilot.click("#--content-tab-tab_settings")
                app.query_one("#settings_cursor_previews", Switch).value = True
                await pilot.click("#settings_save")
                await app.workers.wait_for_complete()
                self.assertEqual(values, [True])
                self.assertTrue(load_settings()["cursor_previews"])
                self.assertIs(app.frida_session, session)
            finally:
                session._script = session._provider_script = None

    async def test_mcp_edits_the_same_provider_hold_and_lists_its_history(self):
        app = NoxenApp(SimpleNamespace(project=None, new_project=str(self.settings_path.parent / "provider-mcp"),
                                       skip_device_scan=True))
        async with app.run_test(size=(140, 48)):
            calls = []
            rpc = SimpleNamespace(resolve_provider=lambda *args: calls.append(args) or True)
            session = SimpleNamespace(_config=SimpleNamespace(target_label=lambda: "demo"),
                                      _script=SimpleNamespace(exports_sync=rpc), is_ready=lambda: True)
            app.provider_service.bind(session)
            app.frida_session = session
            app._connection_state = "connected"
            app._intercept_mode = True
            app.mcp_service.enabled = True
            app.mcp_service.allow_control = True
            session.provider_cb(request())
            app._provider_tick()
            mcp = app.mcp_service
            hold = await mcp.get_provider_interception()
            self.assertEqual((await mcp.interception())["event_type"], "provider")
            edited = {"uri": "content://demo/notes", "selection": "changed"}
            self.assertEqual(await mcp.resolve_provider_interception(
                hold["connection"], "provider-1", "forward", mcp.connection_token(), edited),
                {"accepted": True})
            self.assertEqual(calls, [("provider-1", "forward", edited)])
            session.provider_cb({"noxenEvent": "provider_update", "id": "provider-1", "phase": "request",
                                 "state": "modified_forwarded", "sentArguments": edited})
            session.provider_cb({"noxenEvent": "provider_result", "id": "provider-1", "state": "returned",
                                 "time": 30, "result": {"type": "int", "value": 1}})
            app._provider_tick()
            self.assertEqual((await mcp.list_provider_calls())["calls"][0]["sentArguments"], edited)
            self.assertEqual(app.db._load_all()[0]["outcome"], "modified_forwarded")
            app.frida_session = None
            app.provider_service.bind(None)

    async def test_provider_request_and_response_share_intercept_and_history(self):
        app = NoxenApp(SimpleNamespace(project=None, new_project=str(self.settings_path.parent / "providers"),
                                       skip_device_scan=True))
        async with app.run_test(size=(140, 48)) as pilot:
            service = app.provider_service
            session = SimpleNamespace(_config=SimpleNamespace(target_label=lambda: "demo"), is_ready=lambda: True)
            service.bind(session)
            app.frida_session = session
            app._connection_state = "connected"
            app._intercept_mode = True
            service.receive(service.connection, request())
            app._provider_tick()
            await pilot.pause(.1)
            self.assertEqual(app._current_decision_id, "provider-1")
            self.assertTrue(app._intent_blocked)
            app._enter_edit_mode()
            self.assertIn("content://demo/notes", app.query_one("#edit_form", JsonRequestEditor).area.text)
            service.receive(service.connection, {"noxenEvent": "provider_update", "id": "provider-1", "state": "forwarded"})
            service.receive(service.connection, {"noxenEvent": "provider_response", "id": "provider-1", "state": "held",
                            "phase": "response", "decisionId": "provider-1:response", "time": 20,
                            "result": {"type": "android.database.Cursor", "opaque": True}})
            app._provider_tick()
            await pilot.pause(.1)
            self.assertFalse(app._edit_mode)
            self.assertEqual(app._current_decision_id, "provider-1:response")
            self.assertTrue(app.query_one("#btn_read_cursor").display)
            self.assertTrue(app.query_one("#btn_edit").disabled)
            table = {"columns": ["_display_name"], "rows": [[{"type": "string", "value": "report.txt"}]]}
            service.receive(service.connection, {"noxenEvent": "provider_response", "id": "provider-1", "state": "held",
                            "phase": "response", "decisionId": "provider-1:response", "cursor": table})
            app._provider_tick()
            self.assertFalse(app.query_one("#btn_read_cursor").display)
            self.assertFalse(app.query_one("#btn_edit").disabled)
            intercept_text = "\n".join(line.text for line in app.query_one("#intercept_output", RichLog).lines)
            self.assertIn("[RESPONSE]", intercept_text)
            self.assertIn("_display_name", intercept_text)
            self.assertIn("report.txt", intercept_text)
            app._enter_edit_mode()
            self.assertIn("report.txt", app.query_one("#edit_form", JsonRequestEditor).area.text)
            service.receive(service.connection, {"noxenEvent": "provider_result", "id": "provider-1", "state": "returned",
                            "decisionId": None, "time": 30})
            app._provider_tick()
            self.assertFalse(app._intent_blocked)
            self.assertFalse(app._edit_mode)
            self.assertEqual(len(app._all_intents), 1)
            self.assertEqual(app._all_intents[0]["provider"]["responseAt"], 20)
            self.assertEqual(len(app.db._load_all()), 1)
            app.frida_session = None
            service.bind(None)
