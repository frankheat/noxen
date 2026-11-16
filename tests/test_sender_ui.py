import json
import sqlite3
import tempfile
from unittest.mock import patch
from types import SimpleNamespace

from textual.widgets import TabbedContent, Input, Select, TextArea, DataTable, Label

from noxen.app import NoxenApp
from noxen.sender_ui import SenderPane, SenderRequestModal
from noxen.mcp_service import OperationError
from noxen.monitor_ui import RecordingDialog
from tests.ui_test_case import IsolatedAppTestCase


class SenderUITests(IsolatedAppTestCase):
    async def test_background_launch_can_be_cancelled_or_sent_without_claiming_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(project=None, new_project=directory + "/sender", skip_device_scan=True))
            async with app.run_test(size=(120, 45)) as pilot:
                endpoint = SimpleNamespace(device_id="emulator", is_ready=lambda: True, close=lambda: None,
                    connect=lambda package: {"package": package, "pid": 1, "uid": 10001},
                    activity_context=lambda: {"state": "background", "importance": 400},
                    execute=lambda request, key: {"state": "returned", "result": {"kind": "void"},
                                                  "activityContext": {"state": "background"}})
                service = app.sender_service
                await service.connect(endpoint, "com.google.android.calendar", service.token)
                service.save_request("Open Activity", {"operation": "startActivity", "intent": {"flags": 0x10000000}})
                app.query_one("#main_tabs", TabbedContent).active = "tab_sender"
                app.query_one(SenderPane).refresh_sender()
                await pilot.pause()
                await pilot.click("#sender_send")
                await pilot.pause()
                self.assertIsInstance(app.screen, RecordingDialog)
                await pilot.resize_terminal(60, 24)
                await pilot.pause()
                message = app.screen.query_one("#recording_message", Label)
                self.assertLessEqual(message.region.right, message.parent.content_region.right)
                # The last line must render before the action buttons, even after a resize.
                self.assertTrue("Android." in app.export_screenshot(), "The end of the warning was clipped")
                self.assertLessEqual(message.region.bottom, app.screen.query_one("#recording_cancel").region.y)
                await pilot.click("#recording_cancel")
                await pilot.resize_terminal(120, 45)
                await pilot.pause()
                self.assertEqual(app.db.sender_runs(), [])
                await pilot.click("#sender_send")
                await pilot.pause()
                await pilot.click("#recording_confirm")
                await pilot.pause()
                runs = app.db.sender_runs()
                self.assertEqual(len(runs), 1)
                app.mcp_service.enabled = True
                context = await app.mcp_service.invoke("check_sender_activity_context", expected_sender=service.token)
                self.assertEqual(context["state"], "background")
                result = await app.mcp_service.invoke("get_sender_run", run_id=runs[0]["id"], section="result")
                self.assertEqual(result["result"]["activityLaunch"], "unverified")
                self.assertEqual(result["activityContext"]["state"], "background")

    async def test_captured_control_text_roundtrips_and_save_failure_keeps_editor(self):
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(project=None, new_project=directory + "/sender", skip_device_scan=True))
            async with app.run_test(size=(120, 45)) as pilot:
                saved = app.sender_service.save_request("Control characters", {
                    "operation": "sendBroadcast", "intent": {"action": "one\ntwo\u0000three"}})
                app.push_screen(SenderRequestModal(app.sender_service, saved))
                await pilot.pause()
                modal = app.screen
                self.assertIn("action", modal.json_fields)
                field = modal.query_one("#sender_value_action", Input)
                self.assertNotIn("\n", field.value)
                self.assertEqual(json.loads(field.value), "one\ntwo\u0000three")
                with patch.object(app.db, "save_sender_request", side_effect=sqlite3.OperationalError("disk full")):
                    await pilot.click("#sender_request_save")
                    await pilot.pause()
                    self.assertIs(app.screen, modal)
                await pilot.click("#sender_request_save")
                await pilot.pause()
                self.assertEqual(app.db.sender_request(saved["id"])["request"]["intent"]["action"], "one\ntwo\u0000three")

    async def test_mcp_sender_control_results_and_large_run_sections(self):
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(project=None, new_project=directory + "/sender", skip_device_scan=True))
            async with app.run_test(size=(120, 40)):
                service = app.mcp_service
                service.enabled = True
                token = service.connection_token()
                arguments = dict(name="Request", request={"operation": "sendBroadcast", "intent": {}}, expected_connection=token)
                with self.assertRaises(OperationError):
                    await service.invoke("save_sender_request", **arguments)
                service.allow_control = True
                saved = await service.invoke("save_sender_request", **arguments)
                endpoint = SimpleNamespace(device_id="emulator", is_ready=lambda: True, close=lambda: None,
                    connect=lambda package: {"package": package, "pid": 1, "uid": 10001},
                    execute=lambda request, key: {"state": "returned", "result": {"kind": "void"}})
                with patch("noxen.mcp_service.endpoint_for_app", return_value=endpoint):
                    status = await service.invoke("connect_sender", device_id="emulator", package="test.app", pid=1,
                        expected_sender=app.sender_service.token, expected_connection=token)
                run = await service.invoke("execute_sender_request", request_id=saved["id"], revision=1,
                    expected_sender=status["token"], execution_key="test", expected_connection=token)
                result = await service.invoke("wait_for_sender_run", run_id=run["id"], timeout=5)
                self.assertEqual(result["state"], "returned")
                self.assertEqual(app.query_one("#main_tabs", TabbedContent).active, "tab_home")
                # A large complete run remains readable as separate lossless parts.
                result["request"]["padding"] = "q" * 260000
                result["result"] = {"value": "r" * 350000}
                app.db.save_sender_run(run["id"], result)
                with self.assertRaisesRegex(OperationError, "result_too_large"):
                    await service.invoke("get_sender_run", run_id=run["id"])
                for section in ("request", "result", "sender"):
                    part = await service.invoke("get_sender_run", run_id=run["id"], section=section)
                    self.assertEqual(part[section], result[section])

    async def test_request_editor_saves_null_and_empty_distinctly_and_mcp_conflicts(self):
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(project=None, new_project=directory + "/sender", skip_device_scan=True))
            async with app.run_test(size=(130, 50)) as pilot:
                app.query_one("#main_tabs", TabbedContent).active = "tab_sender"
                await pilot.pause()
                await pilot.click("#sender_new")
                await pilot.pause()
                modal = app.screen
                self.assertIsInstance(modal, SenderRequestModal)
                modal.query_one("#sender_request_name", Input).value = "An empty action"
                await pilot.click("#sender_null_action")
                await pilot.click("#sender_request_save")
                await pilot.pause()
                rows = app.db.sender_requests()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["request"]["intent"]["action"], "")
                self.assertIsNone(rows[0]["request"]["intent"]["component"])
                app.mcp_service.enabled = True
                app.mcp_service.allow_control = True
                await pilot.click("#sender_edit")
                await pilot.pause()
                await app.mcp_service.invoke("save_sender_request", name="MCP change", request=rows[0]["request"],
                    request_id=rows[0]["id"], revision=1, expected_connection=app.mcp_service.connection_token())
                await pilot.click("#sender_request_save")
                await pilot.pause()
                self.assertIsInstance(app.screen, SenderRequestModal)
                self.assertEqual(app.db.sender_requests()[0]["name"], "MCP change")
                await pilot.click("#sender_request_cancel")
                self.assertEqual(app.query_one("#main_tabs", TabbedContent).active, "tab_sender")

    async def test_provider_editor_switches_arguments_and_keeps_operation_fields_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(project=None, new_project=directory + "/sender", skip_device_scan=True))
            async with app.run_test(size=(120, 45)) as pilot:
                app.push_screen(SenderRequestModal(app.sender_service))
                await pilot.pause()
                modal = app.screen
                modal.query_one("#sender_request_name", Input).value = "Query notes"
                modal.query_one("#sender_operation", Select).value = "query"
                await pilot.pause()
                modal.query_one("#sender_value_uri", Input).value = "content://test/notes"
                self.assertFalse(modal.query_one("#sender_field_component").display)
                self.assertTrue(modal.query_one("#sender_field_uri").display)
                self.assertNotIn("intent", json.loads(modal.query_one("#sender_arguments", TextArea).text))
                await pilot.click("#sender_request_save")
                await pilot.pause()
                self.assertEqual(app.db.sender_requests()[0]["request"]["operation"], "query")

    async def test_sender_tabs_and_controls_fit_and_do_not_change_other_tabs(self):
        for theme in ("noxen-dark", "noxen-light"):
            with self.subTest(theme=theme), tempfile.TemporaryDirectory() as directory:
                app = NoxenApp(SimpleNamespace(project=None, new_project=directory + "/sender", skip_device_scan=True))
                async with app.run_test(size=(120, 40)) as pilot:
                    app.theme = theme
                    app.query_one("#main_tabs", TabbedContent).active = "tab_sender"
                    await pilot.pause()
                    pane = app.query_one(SenderPane)
                    for identifier in ("sender_connect", "sender_disconnect", "sender_send", "sender_search"):
                        self.assertLessEqual(pane.query_one(f"#{identifier}").region.right, pane.region.right)
                    app.sender_service.save_request("B", {"operation": "sendBroadcast", "intent": {}})
                    app.sender_service.save_request("A", {"operation": "sendBroadcast", "intent": {}})
                    pane.refresh_sender()
                    await pilot.pause()
                    self.assertEqual([row["name"] for row in pane._requests], ["A", "B"])
                    app.query_one("#sender_search", Input).value = "B"
                    pane.refresh_sender()
                    await pilot.pause()
                    self.assertEqual(app.query_one("#main_tabs", TabbedContent).active, "tab_sender")
                    app.query_one("#sender_views", TabbedContent).active = "sender_runs_view"
                    await pilot.pause()
                    self.assertEqual(app._active_tab, "tab_sender")
                    self.assertTrue(app.check_action("resize_panel_up", ()))
