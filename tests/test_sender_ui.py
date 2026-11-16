import json
import sqlite3
import tempfile
from unittest.mock import patch
from types import SimpleNamespace

from textual.widgets import TabbedContent, Input, Select, TextArea, DataTable, Label

from noxen.app import NoxenApp
from noxen.sender_ui import RequestTab, SenderPane, SenderRequestModal, SenderTabMenu
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
                await pilot.pause(0.5)  # The selected request is read in a worker before Send is enabled.
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
                field = modal.query_one("#sender_value_action", Input)
                self.assertTrue(field.disabled)
                self.assertNotIn("\n", field.value)
                self.assertEqual(json.loads(field.value), "one\ntwo\u0000three")
                await pilot.hover("#sender_field_action")
                await pilot.click("#sender_field_action .scalar_edit")
                await pilot.pause()
                exact = app.screen
                exact.query_one("#sender_text_value", TextArea).load_text("bad\\escape")
                await pilot.click("#sender_text_apply")
                await pilot.pause()
                self.assertIs(app.screen, exact)
                await pilot.click("#sender_text_cancel")
                await pilot.pause()
                self.assertIs(app.screen, modal)
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
                modal.query_one("#sender_value_package", Input).value = r"sample\npackage"
                await pilot.hover("#sender_field_action")
                await pilot.click("#sender_field_action .scalar_edit")
                await pilot.pause()
                app.screen.query_one("#sender_text_state", Select).value = "text"
                app.screen.query_one("#sender_text_value", TextArea).load_text("")
                await pilot.click("#sender_text_apply")
                await pilot.pause()
                await pilot.hover("#sender_field_data")
                await pilot.click("#sender_field_data .scalar_edit")
                await pilot.pause()
                app.screen.query_one("#sender_text_state", Select).value = "text"
                app.screen.query_one("#sender_text_value", TextArea).load_text(r"one\ntwo\u0000")
                await pilot.resize_terminal(60, 24)
                await pilot.pause()
                await pilot.click("#sender_text_apply")
                await pilot.resize_terminal(130, 50)
                await pilot.pause()
                self.assertIs(app.screen, modal)
                self.assertEqual(modal.query_one("#sender_value_action", Input).placeholder, "Empty string")
                await pilot.click("#sender_request_save")
                await pilot.pause()
                rows = app.db.sender_requests()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["request"]["intent"]["action"], "")
                self.assertEqual(rows[0]["request"]["intent"]["data"], "one\ntwo\x00")
                self.assertEqual(rows[0]["request"]["intent"]["package"], r"sample\npackage")
                self.assertNotIn("component", rows[0]["request"]["intent"])
                app.mcp_service.enabled = True
                app.mcp_service.allow_control = True
                await pilot.pause(0.5)
                await pilot.click(app.query_one(RequestTab), button=3)
                await pilot.pause()
                self.assertIsInstance(app.screen, SenderTabMenu)
                await pilot.press("enter")  # Edit is the first entry of the tab menu.
                await pilot.pause()
                await app.mcp_service.invoke("save_sender_request", name="MCP change", request=rows[0]["request"],
                    request_id=rows[0]["id"], revision=1, expected_connection=app.mcp_service.connection_token())
                await pilot.click("#sender_request_save")
                await pilot.pause()
                self.assertIsInstance(app.screen, SenderRequestModal)
                self.assertEqual(app.db.sender_requests()[0]["name"], "MCP change")
                await pilot.click("#sender_request_cancel")
                self.assertEqual(app.query_one("#main_tabs", TabbedContent).active, "tab_sender")

    async def test_new_requests_are_numbered_and_their_runs_can_be_browsed(self):
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(project=None, new_project=directory + "/sender", skip_device_scan=True))
            async with app.run_test(size=(130, 40)) as pilot:
                sent = []
                def execute(request, key):
                    sent.append(key)
                    return {"state": "returned", "result": {"kind": "int", "value": len(sent)}}
                endpoint = SimpleNamespace(device_id="emulator", is_ready=lambda: True, close=lambda: None,
                                           connect=lambda package: {"package": package, "pid": 1, "uid": 10001},
                                           execute=execute)
                service = app.sender_service
                app.query_one("#main_tabs", TabbedContent).active = "tab_sender"
                await pilot.pause()
                pane = app.query_one(SenderPane)
                self.assertTrue(pane.query_one("#sender_disconnect").disabled)  # Nothing to disconnect yet.
                await service.connect(endpoint, "test.app", service.token)
                pane.refresh_sender()
                self.assertFalse(pane.query_one("#sender_disconnect").disabled)
                for expected in ("1", "2"):
                    await pilot.click("#sender_new")
                    await pilot.pause()
                    self.assertEqual(app.screen.query_one("#sender_request_name", Input).value, expected)
                    await pilot.click("#sender_request_save")
                    await pilot.pause(0.5)
                self.assertEqual([str(tab.label) for tab in pane.query(RequestTab)], ["1", "2"])
                self.assertEqual(pane.selected()["name"], "2")
                # The name is the tab label: renaming the request renames its tab.
                await pilot.click("#sender_edit")
                await pilot.pause()
                app.screen.query_one("#sender_request_name", Input).value = "login"
                await pilot.click("#sender_request_save")
                await pilot.pause(0.5)
                self.assertEqual([str(tab.label) for tab in pane.query(RequestTab)], ["1", "login"])
                self.assertEqual(pane.next_name(), "2")

                title = pane.query_one("#sender_result_title", Label)
                self.assertTrue(pane.query_one("#sender_cancel_run").disabled)
                for _ in range(2):
                    await pilot.click("#sender_send")
                    await pilot.pause(0.6)
                runs = [run["id"] for run in service.db.sender_runs()]
                self.assertEqual(str(title.renderable if hasattr(title, "renderable") else title.content), "Result · run 2 of 2")
                self.assertTrue(pane.query_one("#sender_run_newer").disabled)
                await pilot.click("#sender_run_older")
                await pilot.pause(0.6)
                self.assertEqual(pane._run_id, min(runs))
                shown = "\n".join(strip.text for strip in pane.query_one("#sender_request_detail").lines)
                self.assertIn(f"As sent in run #{min(runs)}", shown)  # The request follows the run on screen.
                for button in ("#sender_send", "#sender_edit", "#sender_cancel_run"):
                    widget = pane.query_one(button)  # Border and one space each side: no lopsided padding.
                    self.assertEqual(widget.region.width, len(str(widget.label)) + 4)
                self.assertTrue(pane.query_one("#sender_run_older").disabled)
                await pilot.click("#sender_run_newer")
                await pilot.pause(0.6)
                self.assertIsNone(pane._run_id)  # Back on the latest run, which later sends keep following.

    async def test_history_and_monitor_selections_are_sent_to_sender(self):
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(project=None, new_project=directory + "/sender", skip_device_scan=True))
            async with app.run_test(size=(130, 40)) as pilot:
                tabs = app.query_one("#main_tabs", TabbedContent)
                pane = app.query_one(SenderPane)
                intent = {"component": "test.app/.Receiver", "action": "test.PING", "data": None, "mimeType": None,
                          "package": None, "flags": 16, "categories": [], "selector": None, "clipData": None,
                          "extras": {}, "extrasMeta": {"omitted": 0}}
                tabs.active = "tab_history"
                await pilot.pause()
                self.assertTrue(app.check_action("send_to_sender", ()))
                await pilot.click("#btn_history_sender")  # Nothing selected: nothing is created.
                await pilot.pause()
                self.assertEqual(app.db.sender_requests(), [])

                app._history_selected_entry = {"id": 7, "method": "sendOrderedBroadcast", "intent": intent}
                await pilot.press("ctrl+r")
                await pilot.pause()
                saved = app.db.sender_requests()
                self.assertEqual([(row["name"], row["request"]["operation"]) for row in saved],
                                 [("1", "sendOrderedBroadcast")])
                self.assertEqual(saved[0]["request"]["intent"]["action"], "test.PING")
                self.assertEqual(tabs.active, "tab_history")  # Like a repeater: the source tab stays open.

                # A receiving hook that does not imply an operation asks for one.
                app._history_selected_entry = {"id": 8, "method": "setResult", "intent": intent}
                await pilot.click("#btn_history_sender")
                await pilot.pause()
                self.assertIsInstance(app.screen, SenderTabMenu)
                await pilot.press("down", "enter")  # sendBroadcast
                await pilot.pause()
                self.assertEqual(app.db.sender_request(pane._selected_id)["request"]["operation"], "sendBroadcast")

                # startActivity without NEW_TASK cannot be saved as captured: it opens for review instead.
                app._history_selected_entry = {"id": 9, "method": "startActivity", "intent": intent}
                await pilot.press("ctrl+r")
                await pilot.pause()
                self.assertIsInstance(app.screen, SenderRequestModal)
                self.assertEqual(len(app.db.sender_requests()), 2)
                await pilot.pause(0.5)  # Let the editor finish mounting before closing it.
                await pilot.press("escape")
                await pilot.pause(0.3)
                self.assertNotIsInstance(app.screen, SenderRequestModal)

                await pilot.click("#--content-tab-tab_monitor")
                await pilot.pause(0.3)
                self.assertEqual(app._active_tab, "tab_monitor")
                monitor = app.query_one("#monitor_pane")
                await pilot.click("#monitor_to_sender")  # No event selected: nothing is created.
                await pilot.pause()
                self.assertEqual(len(app.db.sender_requests()), 2)
                events = {"k": {"class": "android.content.ContentResolver", "method": "openInputStream",
                                "types": ["android.net.Uri"],
                                "arguments": [{"type": "android.net.Uri", "value": "content://test/file"}]},
                          "log": {"class": "android.util.Log", "method": "d", "types": [], "arguments": []}}
                # Monitor reloads its events on a timer, so each selection is acted on at once.
                monitor.display_events, monitor.selected = events, "log"
                app.action_send_to_sender()
                self.assertEqual(len(app.db.sender_requests()), 2)  # Not a provider call.
                monitor.display_events, monitor.selected = events, "k"
                app.action_send_to_sender()
                newest = app.db.sender_request(pane._selected_id)
                self.assertEqual((newest["name"], newest["request"]["operation"], newest["request"]["uri"]),
                                 ("3", "openFileDescriptor", "content://test/file"))

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
                self.assertFalse(modal.query("#sender_field_component"))
                self.assertTrue(modal.query_one("#sender_field_uri").display)
                self.assertNotIn("intent", modal.collect_request())
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
                    for identifier in ("sender_connect", "sender_disconnect", "sender_send", "sender_new"):
                        self.assertLessEqual(pane.query_one(f"#{identifier}").region.right, pane.region.right)
                    first = app.sender_service.save_request("B", {"operation": "sendBroadcast", "intent": {}})
                    app.sender_service.save_request("A", {"operation": "sendBroadcast", "intent": {}})
                    pane.refresh_sender()
                    await pilot.pause(0.5)
                    # Tabs follow creation order and are labelled with the request names.
                    self.assertEqual([row["name"] for row in pane._requests], ["B", "A"])
                    tabs = list(pane.query(RequestTab))
                    self.assertEqual([str(tab.label) for tab in tabs], ["B", "A"])
                    self.assertEqual(pane.next_name(), "1")
                    self.assertEqual(pane.selected()["name"], "B")
                    await pilot.click(tabs[1])
                    await pilot.pause(0.5)
                    self.assertEqual(pane.selected()["name"], "A")
                    self.assertTrue(tabs[1].has_class("-selected"))
                    # Request and result share the row below the tabs.
                    request, result = pane.query_one("#sender_request_detail"), pane.query_one("#sender_run_detail")
                    self.assertEqual(request.region.y, result.region.y)
                    self.assertLess(request.region.right, result.region.x)
                    await pilot.click(tabs[0], button=3)
                    await pilot.pause()
                    await pilot.press("down", "down", "enter")  # Remove
                    await pilot.pause(0.5)
                    self.assertEqual([row["id"] for row in app.db.sender_requests()], [pane.selected()["id"]])
                    self.assertNotEqual(pane.selected()["id"], first["id"])
                    self.assertEqual([str(tab.label) for tab in pane.query(RequestTab)], ["A"])
                    self.assertEqual(app.query_one("#main_tabs", TabbedContent).active, "tab_sender")
                    self.assertEqual(app._active_tab, "tab_sender")
                    # The divider between request and result moves sideways.
                    self.assertFalse(app.check_action("resize_panel_up", ()))
                    side = pane.query_one("#sender_request_side")
                    width = side.region.width
                    await pilot.press("alt+right")
                    await pilot.pause()
                    self.assertGreater(side.region.width, width)
                    await pilot.press("alt+left", "alt+left")
                    await pilot.pause()
                    self.assertLess(side.region.width, width)
