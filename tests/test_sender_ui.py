import copy
import sqlite3
import tempfile
from unittest.mock import patch
from types import SimpleNamespace

from textual.widgets import TabbedContent, Input, Label

from noxen.app import NoxenApp
from noxen.sender_ui import NEW_REQUEST_TEXT, RequestTab, SenderPane, SenderRenameModal, SenderTabMenu
from noxen.sender_json_editor import CompletionList
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

    async def test_control_text_null_and_empty_roundtrip_and_a_failed_save_keeps_the_text(self):
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(project=None, new_project=directory + "/sender", skip_device_scan=True))
            async with app.run_test(size=(120, 45)) as pilot:
                saved = app.sender_service.save_request("Control characters", {
                    "operation": "sendBroadcast",
                    "intent": {"action": "one\ntwo\u0000three", "data": None, "mimeType": ""}})
                app.query_one("#main_tabs", TabbedContent).active = "tab_sender"
                await pilot.pause(0.6)
                pane = app.query_one(SenderPane)
                area = pane.editor.area
                # Control characters are written as escapes; null and "" stay distinct from a missing field.
                self.assertIn('"action": "one\\ntwo\\u0000three"', area.text)
                self.assertIn('"data": null', area.text)
                self.assertIn('"mimeType": ""', area.text)
                self.assertNotIn("package", area.text)
                area.focus()
                with patch.object(app.db, "save_sender_request", side_effect=sqlite3.OperationalError("disk full")):
                    # Edited while saving fails, so the automatic save cannot get in first.
                    area.load(area.text.replace('"mimeType": ""', '"mimeType": "", "package": null'))
                    await pilot.pause(1.2)
                    self.assertTrue(pane.editor_dirty())
                await pilot.pause(2.2)  # Saved on its own once it can be.
                self.assertFalse(pane.editor_dirty())
                self.assertEqual(app.db.sender_request(saved["id"])["request"]["intent"], {
                    "action": "one\ntwo\u0000three", "data": None, "mimeType": "", "package": None})

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
                area = pane.editor.area
                for expected in ("1", "2"):
                    await pilot.click("#sender_new")  # Created at once, empty, ready to edit as JSON.
                    await pilot.pause(0.5)
                    self.assertEqual(pane.selected()["name"], expected)
                    self.assertEqual(pane.selected()["request"], {})  # No operation is chosen for the user...
                    self.assertEqual(area.text, NEW_REQUEST_TEXT)
                    self.assertTrue(pane.editor.query_one(CompletionList).display)  # ...the choices are listed.
                    self.assertEqual(area._matches[0][0], "startActivity")
                    self.assertTrue(pane.query_one("#sender_send").disabled)
                    self.assertEqual(str(pane.editor.query_one(".json_status").content), "Choose an operation")
                self.assertEqual([str(tab.label) for tab in pane.query(RequestTab)], ["1", "2"])
                self.assertIs(app.focused, area)
                # Choosing the operation also writes what it needs, and the request is saved.
                await pilot.press("down", "enter")
                await pilot.pause(1.2)
                self.assertEqual(pane.selected()["request"], {"operation": "sendBroadcast", "intent": {}})
                self.assertFalse(pane.query_one("#sender_send").disabled)
                # The name is the tab label: renaming the request renames its tab, and keeps text being typed.
                area.load('{\n    "operation": "sendBroadcast",\n    "intent": {"flags": 16}\n}')
                await pilot.pause()
                await pilot.click(list(pane.query(RequestTab))[1], button=3)
                await pilot.pause()
                await pilot.press("enter")  # Rename is the first entry of the tab menu.
                await pilot.pause()
                self.assertIsInstance(app.screen, SenderRenameModal)
                app.screen.query_one("#sender_rename", Input).value = "login"
                await pilot.press("enter")
                await pilot.pause(0.5)
                self.assertEqual([str(tab.label) for tab in pane.query(RequestTab)], ["1", "login"])
                self.assertEqual(pane.next_name(), "2")
                self.assertFalse(pane.editor.query_one(".json_status").has_class("error"))
                await pilot.pause(1.2)
                self.assertEqual(pane.selected()["request"]["intent"]["flags"], 16)
                self.assertEqual(pane.selected()["name"], "login")

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
                # The request follows the run on screen, read only.
                self.assertEqual(pane._editor_key, ("run", min(runs)))
                self.assertTrue(pane.editor.area.read_only)
                for button in ("#sender_send", "#sender_cancel_run"):
                    widget = pane.query_one(button)  # Border and one space each side: no lopsided padding.
                    self.assertEqual(widget.region.width, len(str(widget.label)) + 4)
                self.assertTrue(pane.query_one("#sender_run_older").disabled)
                await pilot.click("#sender_run_newer")
                await pilot.pause(0.6)
                self.assertIsNone(pane._run_id)  # Back on the latest run, which later sends keep following.

    async def test_tab_menu_closes_other_tabs_and_tabs_to_one_side(self):
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(project=None, new_project=directory + "/sender", skip_device_scan=True))
            async with app.run_test(size=(130, 40)) as pilot:
                service = app.sender_service
                for name in "ABCDE":
                    service.save_request(name, {})
                app.query_one("#main_tabs", TabbedContent).active = "tab_sender"
                await pilot.pause(0.6)
                pane = app.query_one(SenderPane)
                names = lambda: [str(tab.label) for tab in pane.query(RequestTab)]
                tab = lambda name: next(t for t in pane.query(RequestTab) if str(t.label) == name)

                async def close(name, label, confirm=True):
                    await pilot.click(tab(name), button=3)
                    await pilot.pause()
                    menu = app.screen.query_one("OptionList")
                    labels = [str(menu.get_option_at_index(i).prompt) for i in range(menu.option_count)]
                    menu.highlighted = labels.index(label)
                    await pilot.press("enter")
                    await pilot.pause()
                    self.assertIsInstance(app.screen, RecordingDialog)  # Requests are deleted: confirmed first.
                    await pilot.click("#recording_confirm" if confirm else "#recording_cancel")
                    await pilot.pause(0.6)
                    return labels

                # Only the directions that have tabs are offered.
                await pilot.click(tab("A"), button=3)
                await pilot.pause()
                menu = app.screen.query_one("OptionList")
                labels = [str(menu.get_option_at_index(i).prompt) for i in range(menu.option_count)]
                self.assertIn("Close tabs to the right", labels)
                self.assertNotIn("Close tabs to the left", labels)
                await pilot.press("escape")
                await pilot.pause()

                await close("C", "Close tabs to the right", confirm=False)
                self.assertEqual(names(), list("ABCDE"))  # Cancelled: nothing removed.
                await close("C", "Close tabs to the right")
                self.assertEqual(names(), list("ABC"))
                await close("B", "Close tabs to the left")
                self.assertEqual(names(), list("BC"))
                await close("C", "Close other tabs")
                self.assertEqual(names(), ["C"])
                self.assertEqual([row["name"] for row in app.db.sender_requests()], ["C"])
                self.assertEqual(pane.selected()["name"], "C")

    async def test_request_json_is_edited_in_place_with_completion_and_sent(self):
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(project=None, new_project=directory + "/sender", skip_device_scan=True))
            async with app.run_test(size=(130, 40)) as pilot:
                sent = []
                endpoint = SimpleNamespace(device_id="emulator", is_ready=lambda: True, close=lambda: None,
                                           connect=lambda package: {"package": package, "pid": 1, "uid": 10001},
                                           execute=lambda request, key: (sent.append(request), {
                                               "state": "returned", "result": {"kind": "void"}})[1])
                service = app.sender_service
                await service.connect(endpoint, "test.app", service.token)
                first = service.save_request("1", {"operation": "sendBroadcast", "intent": {"action": "test.PING"}})
                service.save_request("2", {"operation": "query", "uri": "content://test/notes"})
                app.query_one("#main_tabs", TabbedContent).active = "tab_sender"
                await pilot.pause(0.6)
                pane = app.query_one(SenderPane)
                area = pane.editor.area
                self.assertEqual(area.text, '{\n    "operation": "sendBroadcast",\n    "intent": {\n'
                                            '        "action": "test.PING"\n    }\n}')
                self.assertTrue(area._highlights[1])  # Colours do not depend on a grammar package.

                # A new line, two letters, Enter: the name completes, with the comma the line above lacked.
                area.focus()
                area.move_cursor((3, len('        "action": "test.PING"')))
                await pilot.press("enter", "e", "x")
                await pilot.pause(0.2)
                self.assertTrue(area.popup.display)
                await pilot.press("enter")
                await pilot.pause(0.2)
                await pilot.press("S", "t")
                await pilot.pause(0.2)
                await pilot.press("enter")
                await pilot.pause(0.2)
                await pilot.press("t", "o", "k")
                await pilot.pause(0.2)
                self.assertIn('        "action": "test.PING",\n        "extras": {\n'
                              '            "tok": {"type": "String", "value": ""}\n        }', area.text)
                self.assertTrue(pane.editor_dirty())

                # An opening brace closes itself on its own line; folding keeps the request intact.
                area.move_cursor(area.document.end)
                await pilot.press("{")
                self.assertTrue(area.text.endswith("}{\n    \n}"))
                await pilot.press("ctrl+z")
                area.move_cursor((4, 0))
                await pilot.press("f2")
                await pilot.pause(0.2)
                self.assertIn('"extras": {⋯₁}', area.text)

                # Unsaved text survives a visit to another request, and Send sends what is on screen.
                tabs = list(pane.query(RequestTab))
                await pilot.click(tabs[1])
                await pilot.pause(0.6)
                self.assertIn('"query"', area.text)
                await pilot.click(tabs[0])
                await pilot.pause(0.6)
                self.assertIn('"extras": {⋯₁}', area.text)
                await pilot.click("#sender_send")
                await pilot.pause(0.6)
                self.assertEqual(sent[0]["intent"], {"action": "test.PING",
                                                     "extras": {"tok": {"type": "String", "value": ""}}})
                self.assertFalse(pane.editor_dirty())

                # A request changed elsewhere is shown as changed; text here that never became valid is dropped.
                area.focus()
                area.move_cursor(area.document.end)
                await pilot.press("x")
                current = service.db.sender_request(first["id"])
                service.save_request("1", {"operation": "sendBroadcast", "intent": {"action": "from.elsewhere"}},
                                     first["id"], current["revision"])
                pane.refresh_sender()
                await pilot.pause(0.6)
                self.assertIn("from.elsewhere", area.text)
                self.assertFalse(pane.editor_dirty())
                self.assertEqual(service.db.sender_request(first["id"])["request"]["intent"]["action"], "from.elsewhere")
                # While the editor still shows another request, saving or sending does nothing.
                pane._selected_id = service.db.sender_requests()[1]["id"] if service.db.sender_requests()[1]["id"] != first["id"] \
                    else service.db.sender_requests()[0]["id"]
                pane._requests = service.db.sender_requests()
                self.assertIsNone(pane.save_editor())
                pane.select_request(first["id"])
                await pilot.pause(0.6)

                # Invalid text is not saved, and Send does not send it.
                before = service.db.sender_request(first["id"])
                area.focus()
                area.move_cursor(area.document.end)
                await pilot.press("x")
                await pilot.pause(1.2)
                self.assertEqual(service.db.sender_request(first["id"]), before)
                await pilot.click("#sender_send")
                await pilot.pause(0.4)
                self.assertTrue(pane.editor.query_one(".json_status").has_class("error"))
                self.assertEqual(len(sent), 1)

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

                # The same capture can be read as JSON, in the form Sender uses, and back as details.
                detail = app.query_one("#history_detail")
                shown = lambda: "\n".join(strip.text for strip in detail.lines)
                app._refresh_history_detail()
                self.assertIn("[HOOK]", shown())
                self.assertTrue(app.check_action("toggle_detail_view", ()))
                await pilot.press("f4")
                await pilot.pause()
                self.assertFalse(app.query("#btn_history_view"))  # A shortcut only, shown in the footer.
                self.assertIn('"hook": "sendOrderedBroadcast()"', shown())  # Shown for reading only...
                self.assertIn('"operation": "sendOrderedBroadcast"', shown())  # The hooked call itself.
                self.assertNotIn("hook", saved[0]["request"])  # ...To Sender converts it away.
                self.assertIn('"action": "test.PING"', shown())
                self.assertNotIn("[HOOK]", shown())
                await pilot.press("f4")
                await pilot.pause()
                self.assertIn("[HOOK]", shown())

                # A capture with gaps is offered without them, and only if the user accepts.
                gapped = copy.deepcopy(intent)
                gapped["extras"] = {"obj": {"structuredVersion": 1, "structured": {"kind": "object", "type": "test.Custom"}},
                                    "n": {"structuredVersion": 1, "structured": {
                                        "kind": "scalar", "type": "java.lang.Integer", "value": "3"}}}
                app._history_selected_entry = {"id": 10, "method": "sendBroadcast", "intent": gapped}
                before = len(app.db.sender_requests())
                await pilot.press("ctrl+r")
                await pilot.pause()
                self.assertIsInstance(app.screen, RecordingDialog)
                self.assertIn("test.Custom", str(app.screen.query_one("#recording_message", Label).render()))
                await pilot.click("#recording_cancel")
                await pilot.pause()
                self.assertEqual(len(app.db.sender_requests()), before)
                await pilot.press("ctrl+r")
                await pilot.pause()
                await pilot.click("#recording_confirm")
                await pilot.pause(0.4)
                self.assertEqual(app.db.sender_request(pane._selected_id)["request"]["intent"]["extras"],
                                 {"n": {"type": "int", "value": 3}})
                for row in app.db.sender_requests()[before:]:  # Keep the numbering below as it was.
                    app.sender_service.remove_request(row["id"], row["revision"])
                pane.refresh_sender()
                await pilot.pause(0.4)

                # A receiving hook that does not imply an operation asks for one.
                app._history_selected_entry = {"id": 8, "method": "setResult", "intent": intent}
                await pilot.click("#btn_history_sender")
                await pilot.pause()
                self.assertIsInstance(app.screen, SenderTabMenu)
                await pilot.press("down", "enter")  # sendBroadcast
                await pilot.pause()
                self.assertEqual(app.db.sender_request(pane._selected_id)["request"]["operation"], "sendBroadcast")

                # startActivity without NEW_TASK cannot be saved as captured: it arrives as unsaved text to repair.
                app._history_selected_entry = {"id": 9, "method": "startActivity", "intent": intent}
                await pilot.press("ctrl+r")
                await pilot.pause(0.6)
                self.assertEqual(len(app.db.sender_requests()), 3)
                self.assertEqual(app.db.sender_request(pane._selected_id)["request"], {})  # Nothing invented.
                self.assertIn('"operation": "startActivity"', pane.editor.area.text)
                self.assertIn('"action": "test.PING"', pane.editor.area.text)
                self.assertTrue(pane.editor_dirty())

                await pilot.click("#--content-tab-tab_monitor")
                await pilot.pause(0.3)
                self.assertEqual(app._active_tab, "tab_monitor")
                monitor = app.query_one("#monitor_pane")
                await pilot.click("#monitor_to_sender")  # No event selected: nothing is created.
                await pilot.pause()
                self.assertEqual(len(app.db.sender_requests()), 3)
                events = {"k": {"class": "android.content.ContentResolver", "method": "openInputStream",
                                "types": ["android.net.Uri"],
                                "arguments": [{"type": "android.net.Uri", "value": "content://test/file"}]},
                          "log": {"class": "android.util.Log", "method": "d", "types": [], "arguments": []}}
                # Monitor reloads its events on a timer, so each selection is acted on at once.
                self.assertTrue(monitor.query_one("#monitor_to_sender").disabled)  # Nothing selected.
                monitor.display_events, monitor.selected = events, "log"
                monitor.refresh_to_sender()
                self.assertTrue(monitor.query_one("#monitor_to_sender").disabled)  # Not a call Sender can repeat...
                self.assertIsNone(app.check_action("send_to_sender", ()))  # ...nor through Ctrl+R.
                app.action_send_to_sender()
                self.assertEqual(len(app.db.sender_requests()), 3)
                monitor.display_events, monitor.selected = events, "k"
                monitor.refresh_to_sender()
                self.assertFalse(monitor.query_one("#monitor_to_sender").disabled)
                self.assertTrue(app.check_action("send_to_sender", ()))
                app.action_send_to_sender()
                newest = app.db.sender_request(pane._selected_id)
                self.assertEqual((newest["name"], newest["request"]["operation"], newest["request"]["uri"]),
                                 ("4", "openFileDescriptor", "content://test/file"))

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
                    await pilot.press("down", "down", "enter")  # Close
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
