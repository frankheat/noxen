import copy
import json
import sqlite3
import tempfile
from unittest.mock import patch
from types import SimpleNamespace

from textual.widgets import TabbedContent, Input, Label, OptionList, Select

from noxen.app import NoxenApp
from noxen.sender_ui import NEW_REQUEST_TEXT, RequestTab, SenderPane, SenderRenameModal, SenderTabMenu
from noxen.sender_json_editor import CompletionList
from noxen.mcp_service import OperationError
from noxen.textual_compat import is_select_empty
from noxen.monitor_ui import RecordingDialog
from tests.ui_test_case import IsolatedAppTestCase


async def settle(pilot, condition, timeout=5.0):
    """Wait for `condition()`: Sender refreshes on a timer and loads its tabs in a worker,
    both later on a busy machine. The assertion that follows reports any failure."""
    for _ in range(int(timeout / 0.1)):
        if condition():
            return
        await pilot.pause(0.1)


class SenderUITests(IsolatedAppTestCase):
    async def test_history_activity_flag_completion_clears_draft_warning_disconnected(self):
        app = NoxenApp(SimpleNamespace(project=None, new_project=str(self.settings_path.parent / "history-flag"),
                                       skip_device_scan=True))
        async with app.run_test(size=(120, 42)) as pilot:
            tabs = app.query_one("#main_tabs", TabbedContent)
            tabs.active = "tab_history"
            await pilot.pause()
            app._history_selected_entry = {"id": 1, "method": "startActivity", "intent": {
                "component": "dev.noxen.playground/.InvitationApprovalActivity", "action": None,
                "data": None, "mimeType": None, "package": None, "flags": 0, "categories": [],
                "selector": None, "clipData": None, "extras": None}}
            await pilot.press("ctrl+r")
            pane = app.query_one(SenderPane)
            await settle(pilot, lambda: pane._editor_key is not None and "startActivity" in pane.editor.area.text)
            tabs.active = "tab_sender"
            await pilot.pause()
            area = pane.editor.area
            status = pane.editor.query_one(".json_status")
            self.assertIn("FLAG_ACTIVITY_NEW_TASK", str(status.content))
            self.assertEqual(app.sender_service.status()["state"], "disconnected")
            self.assertIn('"flags": []', area.text)
            area.focus()
            area.move_cursor(area.location(area.text.index('"flags": []') + len('"flags": [')))
            await pilot.press("ctrl+space")
            self.assertTrue(area.popup.display)
            self.assertEqual(area._matches[0][0], "FLAG_ACTIVITY_NEW_TASK")
            await pilot.press("enter")
            self.assertIn('"flags": ["FLAG_ACTIVITY_NEW_TASK"]', area.text)
            self.assertEqual(str(status.content), "")
            self.assertFalse(status.has_class("error"))
            await settle(pilot, lambda: pane.selected()["request"].get("operation") == "startActivity")
            self.assertIsNone(app.db.sender_draft(*pane._editor_key))
            # The same status update applies to ordinary edits, including pasted text.
            valid_text = area.text
            area.load(valid_text.replace('"operation": "startActivity"', '"operation": "unknown"'))
            await settle(pilot, lambda: "Unsupported Sender operation" in str(status.content))
            area.load(valid_text)
            await settle(pilot, lambda: str(status.content) == "")
            self.assertFalse(status.has_class("error"))

    async def test_result_shows_query_summary_and_switches_to_raw_and_details(self):
        project = self.settings_path.parent / "result"
        app = NoxenApp(SimpleNamespace(project=None, new_project=str(project), skip_device_scan=True))
        async with app.run_test(size=(120, 45)) as pilot:
            saved = app.sender_service.save_request("Notes", {"operation": "query", "uri": "content://dev.example/notes"})
            run_id = app.db.create_sender_run("result-preview", {
                "request_id": saved["id"], "revision": saved["revision"], "request": saved["request"],
                "name": saved["name"], "sender": {"package": "dev.example", "uid": 10001, "pid": 1},
                "device": "emulator", "createdAt": "host time", "state": "returned",
                "result": {"kind": "cursor", "columns": ["title", "attachment"],
                           "rows": [[{"type": "String", "value": "Release notes"},
                                     {"type": "blob", "captured": False}]], "truncated": False},
            })
            self.assertTrue(await pilot.click("#--content-tab-tab_sender"))
            pane = app.query_one(SenderPane)
            log = pane.query_one("#sender_run_detail")
            rendered = lambda: "\n".join(line.text for line in log.lines)  # noqa: E731
            await settle(pilot, lambda: "Partial result" in rendered())
            self.assertIn(f"#{run_id}", rendered())
            self.assertIn("Release notes", rendered())
            self.assertIn("Cells not captured", rendered())
            self.assertTrue(await pilot.click("#sender_result_raw"))
            await settle(pilot, lambda: "[RAW RESULT]" in rendered())
            self.assertIn("[RAW RESULT]", rendered())
            self.assertIn("truncated", rendered())
            self.assertTrue(await pilot.click("#sender_result_details"))
            await settle(pilot, lambda: "[TIMING]" in rendered())
            self.assertIn("[SENDER]", rendered())
            self.assertNotIn("[RAW RESULT]", rendered())
            self.assertTrue(await pilot.click("#sender_result_details"))
            await settle(pilot, lambda: "Release notes" in rendered())
            await pilot.resize_terminal(60, 40)
            await settle(pilot, lambda: "Release notes" in rendered())
            self.assertIn("Release notes", rendered())
            self.assertLessEqual(pane.query_one("#sender_result_details").region.right, pane.region.right)

    async def test_invalid_drafts_survive_autosave_quit_and_reopen_without_becoming_sendable(self):
        path = self.settings_path.parent / "drafts.noxen"
        app = NoxenApp(SimpleNamespace(project=None, new_project=str(path), skip_device_scan=True))
        valid = {"operation": "sendBroadcast", "intent": {"action": "before"}}
        invalid_json = '{\n    "operation": "sendBroadcast",'
        invalid_request = '{"operation":"startActivity","intent":{"flags":[]}}'
        async with app.run_test(size=(120, 42)) as pilot:
            service = app.sender_service
            first = service.save_request("1", valid)
            second = service.save_request("2", {})
            app.query_one("#main_tabs").active = "tab_sender"
            pane = app.query_one(SenderPane)
            await settle(pilot, lambda: pane._editor_key == (first["id"], first["revision"]))
            pane.editor.area.load(invalid_json)
            await settle(pilot, lambda: app.db.sender_draft(first["id"], first["revision"]) is not None)
            status = pane.editor.query_one(".json_status")
            self.assertTrue(status.has_class("error"))
            self.assertEqual(str(status.content), app.db.sender_draft(first["id"], first["revision"])[1])
            self.assertEqual(app.db.sender_request(first["id"]), first)
            pane.select_request(second["id"])
            await settle(pilot, lambda: pane._editor_key == (second["id"], second["revision"]))
            pane.editor.area.load(invalid_request)
            with patch.object(app.db, "save_sender_draft", side_effect=sqlite3.OperationalError("disk full")):
                await pilot.press("ctrl+q")  # Flush even if the debounce has not fired yet.
                await settle(pilot, lambda: isinstance(app.screen, RecordingDialog))
                warning = str(app.screen.query_one("#recording_message").render())
                self.assertIn("Could not save draft", warning)
                self.assertIn("disk full", warning)
            app.screen.dismiss(False)  # Retry once storage is available again.
            await pilot.pause()

        reopened = NoxenApp(SimpleNamespace(project=str(path), new_project=None, skip_device_scan=True))
        async with reopened.run_test(size=(120, 42)) as pilot:
            service = reopened.sender_service
            sent = []
            endpoint = SimpleNamespace(device_id="emulator", is_ready=lambda: True, close=lambda: None,
                                       connect=lambda package: {"package": package, "pid": 1, "uid": 10001},
                                       execute=lambda *args: sent.append(args))
            await service.connect(endpoint, "test.app", service.token)
            reopened.query_one("#main_tabs").active = "tab_sender"
            pane = reopened.query_one(SenderPane)
            await settle(pilot, lambda: pane.editor.area.text == invalid_json)
            self.assertEqual(pane.editor.area.text, invalid_json)
            status = pane.editor.query_one(".json_status")
            self.assertTrue(status.has_class("error"))
            self.assertEqual(str(status.content), reopened.db.sender_draft(first["id"], first["revision"])[1])
            await settle(pilot, lambda: not pane.query_one("#sender_send").disabled)
            self.assertFalse(pane.query_one("#sender_send").disabled)
            await pilot.click("#sender_send")
            self.assertEqual(sent, [])
            pane.select_request(second["id"])
            await settle(pilot, lambda: pane.editor.area.text == invalid_request)
            self.assertEqual(pane.editor.area.text, invalid_request)
            self.assertIn("FLAG_ACTIVITY_NEW_TASK", str(pane.editor.query_one(".json_status").content))
            self.assertEqual(reopened.db.sender_request(second["id"]), second)
            self.assertTrue(pane.query_one("#sender_send").disabled)
            pane.editor.area.load(NEW_REQUEST_TEXT)
            await settle(pilot, lambda: reopened.db.sender_draft(second["id"], second["revision"]) is None)
            self.assertIsNone(reopened.db.sender_draft(second["id"], second["revision"]))
            self.assertEqual(reopened.db.sender_request(second["id"]), second)
            pane.select_request(first["id"])
            await settle(pilot, lambda: pane.editor.area.text == invalid_json)
            pane.editor.area.load('{"operation":"sendBroadcast","intent":{"action":"fixed"}}')
            await settle(pilot, lambda: reopened.db.sender_request(first["id"])["revision"] > first["revision"])
            self.assertFalse(pane.query_one("#sender_send").disabled)
            self.assertEqual(str(status.content), "")
            self.assertFalse(status.has_class("error"))
            repaired = reopened.db.sender_request(first["id"])
            self.assertEqual(repaired["request"]["intent"]["action"], "fixed")
            self.assertIsNone(reopened.db.sender_draft(first["id"], first["revision"]))
            self.assertIsNone(reopened.db.sender_draft(first["id"], repaired["revision"]))

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
                    self.assertIn("Could not save draft: disk full", str(pane.editor.query_one(".json_status").content))
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
                # A new project already has one empty request, so there is always something to edit.
                labels = lambda: [str(tab.label) for tab in pane.query(RequestTab)]  # noqa: E731
                await settle(pilot, lambda: labels() == ["1"] and pane.selected() is not None)
                self.assertEqual([str(tab.label) for tab in pane.query(RequestTab)], ["1"])
                self.assertEqual(pane.selected()["request"], {})
                for expected in ("2", "3"):
                    await pilot.click("#sender_new")  # Created at once, empty, ready to edit as JSON.
                    await settle(pilot, lambda: pane.selected() is not None and pane.selected()["name"] == expected
                                 and area.text == NEW_REQUEST_TEXT)
                    await pilot.pause(0.2)  # The operations are listed after the text is shown.
                    self.assertEqual(pane.selected()["name"], expected)
                    self.assertEqual(pane.selected()["request"], {})  # No operation is chosen for the user...
                    self.assertEqual(area.text, NEW_REQUEST_TEXT)
                    self.assertTrue(pane.editor.query_one(CompletionList).display)  # ...the choices are listed.
                    self.assertEqual(area._matches[0][0], "startActivity")
                    self.assertTrue(pane.query_one("#sender_send").disabled)
                    self.assertEqual(str(pane.editor.query_one(".json_status").content), "")
                self.assertEqual([str(tab.label) for tab in pane.query(RequestTab)], ["1", "2", "3"])
                self.assertIs(app.focused, area)
                # Choosing the operation also writes what it needs, and the request is saved.
                await pilot.press("down", "enter")
                await pilot.pause(1.2)
                self.assertEqual(pane.selected()["request"]["operation"], "sendBroadcast")
                self.assertIsNone(pane.selected()["request"]["receiverPermission"])
                self.assertFalse(pane.query_one("#sender_send").disabled)
                # The name is the tab label: renaming the request renames its tab, and keeps text being typed.
                area.load('{\n    "operation": "sendBroadcast",\n    "intent": {"flags": 16}\n}')
                await pilot.pause()
                await pilot.click(list(pane.query(RequestTab))[2], button=3)
                await pilot.pause()
                await pilot.press("enter")  # Rename is the first entry of the tab menu.
                await pilot.pause()
                self.assertIsInstance(app.screen, SenderRenameModal)
                app.screen.query_one("#sender_rename", Input).value = "login"
                await pilot.press("enter")
                await pilot.pause(0.5)
                self.assertEqual([str(tab.label) for tab in pane.query(RequestTab)], ["1", "2", "login"])
                self.assertEqual(pane.next_name(), "3")
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
                original_run = service.get_run(min(runs))
                self.assertEqual(pane._editor_run_id, min(runs))
                self.assertFalse(area.read_only)
                self.assertEqual(json.loads(area.text), original_run["request"])
                area.load('{"operation":"sendBroadcast","intent":{"action":"edited"}}')
                await settle(pilot, lambda: pane.selected()["request"]["intent"].get("action") == "edited"
                             and not pane.query_one("#sender_send").disabled)
                self.assertEqual(pane._run_id, min(runs))
                self.assertEqual(service.get_run(min(runs))["request"], original_run["request"])
                for button in ("#sender_send", "#sender_cancel_run"):
                    widget = pane.query_one(button)  # Border and one space each side: no lopsided padding.
                    self.assertEqual(widget.region.width, len(str(widget.label)) + 4)
                self.assertTrue(pane.query_one("#sender_run_older").disabled)
                await pilot.click("#sender_run_newer")
                await pilot.pause(0.6)
                self.assertIsNone(pane._run_id)  # Back on the latest run, which later sends keep following.
                self.assertEqual(json.loads(area.text)["intent"]["action"], "edited")
                await pilot.click("#sender_run_older")
                await settle(pilot, lambda: pane._editor_run_id == min(runs)
                             and not pane.query_one("#sender_send").disabled)
                await pilot.click("#sender_send")
                await settle(pilot, lambda: len(pane._run_ids) == 3 and pane._editor_run_id is None)
                self.assertEqual(service.get_run(pane._run_ids[0])["request"], original_run["request"])

    async def test_the_only_device_is_selected_and_a_rescan_keeps_the_choice(self):
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(project=None, new_project=directory + "/sender", skip_device_scan=True))
            async with app.run_test(size=(130, 40)) as pilot:
                app.query_one("#main_tabs", TabbedContent).active = "tab_sender"
                await pilot.pause()
                pane = app.query_one(SenderPane)
                select = pane.query_one("#sender_device", Select)
                loaded = []
                with patch.object(pane, "load_applications", side_effect=lambda device, _: loaded.append(device)):
                    first = SimpleNamespace(name="Emulator", id="emulator-5554")
                    app._home_devices = [first]
                    pane.refresh_sender()
                    await pilot.pause()
                    self.assertEqual(select.value, "emulator-5554")
                    self.assertEqual(loaded, ["emulator-5554"])  # Its apps are listed without a click.
                    app._home_devices = [first, SimpleNamespace(name="Phone", id="usb-1")]
                    pane.refresh_sender()
                    await pilot.pause()
                    self.assertEqual(select.value, "emulator-5554")
                    app._home_devices = [SimpleNamespace(name="Phone", id="usb-1"),
                                         SimpleNamespace(name="Tablet", id="usb-2")]
                    pane.refresh_sender()
                    await pilot.pause()
                    self.assertTrue(is_select_empty(select.value))  # Several new devices: the user chooses.

    async def test_tab_menu_closes_other_tabs_and_tabs_to_one_side(self):
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(project=None, new_project=directory + "/sender", skip_device_scan=True))
            async with app.run_test(size=(130, 40)) as pilot:
                service = app.sender_service
                runs = {}
                for name in "ABCDE":
                    saved = service.save_request(name, {"operation": "sendBroadcast", "intent": {}})
                    run = {**saved, "request_id": saved["id"], "state": "returned",
                           "sender": {"package": "dev.example", "uid": 10001, "pid": 1},
                           "device": "emulator", "createdAt": "host time", "result": {"kind": "void"}}
                    runs[name] = app.db.create_sender_run(name, run)
                    if name == "E":
                        service.unsaved[runs[name]] = dict(run, id=runs[name])
                app.query_one("#main_tabs", TabbedContent).active = "tab_sender"
                pane = app.query_one(SenderPane)
                names = lambda: [str(tab.label) for tab in pane.query(RequestTab)]
                tab = lambda name: next(t for t in pane.query(RequestTab) if str(t.label) == name)
                await settle(pilot, lambda: names() == list("ABCDE") and pane.selected() is not None)
                self.assertEqual(names(), list("ABCDE"))

                async def open_menu(name):
                    target = tab(name)
                    target.scroll_visible()
                    await pilot.pause()
                    self.assertTrue(await pilot.click(target, button=3))
                    # The editor also contains an OptionList. Wait until the
                    # context menu is mounted and owns keyboard focus.
                    await settle(pilot, lambda: isinstance(app.screen, SenderTabMenu)
                                 and isinstance(app.focused, OptionList) and app.focused.screen is app.screen)
                    self.assertIsInstance(app.screen, SenderTabMenu)
                    menu = app.screen.query_one(OptionList)
                    self.assertIs(app.focused, menu)
                    return menu, [str(menu.get_option_at_index(i).prompt) for i in range(menu.option_count)]

                async def close(name, label, remaining):
                    menu, labels = await open_menu(name)
                    menu.highlighted = labels.index(label)
                    await pilot.press("enter")
                    await settle(pilot, lambda: names() == list(remaining))
                    self.assertEqual(names(), list(remaining))
                    self.assertNotIsInstance(app.screen, RecordingDialog)
                    self.assertEqual({run["id"] for run in app.db.sender_runs()}, {runs[name] for name in remaining})

                # Only the directions that have tabs are offered.
                _, labels = await open_menu("A")
                self.assertNotIn("Duplicate", labels)
                self.assertIn("Close tabs to the right", labels)
                self.assertNotIn("Close tabs to the left", labels)
                await pilot.press("escape")
                await settle(pilot, lambda: not isinstance(app.screen, SenderTabMenu))
                self.assertNotIsInstance(app.screen, SenderTabMenu)

                await close("C", "Close tabs to the right", "ABC")
                self.assertNotIn(runs["E"], service.unsaved)
                await close("B", "Close tabs to the left", "BC")
                await close("C", "Close other tabs", "C")
                self.assertEqual([row["name"] for row in app.db.sender_requests()], ["C"])
                self.assertEqual(pane.selected()["name"], "C")

                # Closing the last tab leaves a new empty request, ready to edit.
                menu, labels = await open_menu("C")
                menu.highlighted = labels.index("Close")
                await pilot.press("enter")
                await settle(pilot, lambda: names() == ["1"] and app.focused is pane.editor.area)
                self.assertEqual(names(), ["1"])
                self.assertEqual(pane.selected()["request"], {})
                self.assertEqual(app.db.sender_runs(), [])
                self.assertEqual(pane.editor.area.text, NEW_REQUEST_TEXT)
                self.assertIs(app.focused, pane.editor.area)  # Like +: the operations are listed.
                # Removed elsewhere (e.g. over MCP), the last request is replaced too.
                row = app.db.sender_requests()[0]
                service.remove_request(row["id"], row["revision"])
                await settle(pilot, lambda: len(app.db.sender_requests()) == 1 and names() == ["1"])
                self.assertEqual(names(), ["1"])
                self.assertEqual(len(app.db.sender_requests()), 1)

    async def test_sender_shortcut_duplicates_the_selected_request(self):
        app = NoxenApp(SimpleNamespace(project=None, new_project=str(self.settings_path.parent / "duplicate"),
                                       skip_device_scan=True))
        async with app.run_test(size=(130, 40)) as pilot:
            request = {"operation": "sendBroadcast", "intent": {"action": "demo"}}
            saved = app.sender_service.save_request("Example", request)
            self.assertTrue(await pilot.click("#--content-tab-tab_sender"))
            pane = app.query_one(SenderPane)
            await settle(pilot, lambda: pane._editor_key == (saved["id"], saved["revision"]))
            pane.editor.area.focus()
            await pilot.press("ctrl+r")
            await settle(pilot, lambda: pane.selected() is not None and pane.selected()["name"] == "Example copy")
            self.assertEqual(pane.selected()["name"], "Example copy")
            self.assertEqual(pane.selected()["request"], request)
            self.assertNotEqual(pane.selected()["id"], saved["id"])
            self.assertEqual(app.db.sender_request(saved["id"])["request"], request)

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
                # The text is valid, so it is pending or, on a slow machine, already saved on its own.
                saved = service.db.sender_request(first["id"])["request"]["intent"]
                self.assertTrue(pane.editor_dirty() or saved.get("extras") == {"tok": {"type": "String", "value": ""}})

                # An opening brace closes itself on its own line; folding keeps the request intact.
                area.move_cursor(area.document.end)
                await pilot.press("{")
                self.assertTrue(area.text.endswith("}{\n    \n}"))
                await pilot.press("ctrl+z")
                area.move_cursor((4, 0))
                await pilot.press("ctrl+o")
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

                # Send validates the visible text even before autosave can run.
                before = service.db.sender_request(first["id"])
                send_button = pane.query_one("#sender_send")
                with patch("noxen.sender_ui.AUTOSAVE_DELAY", 60):
                    area.focus()
                    area.move_cursor(area.document.end)
                    await pilot.press("x")
                    self.assertFalse(send_button.disabled)
                    self.assertIsNone(app.db.sender_draft(first["id"], before["revision"]))
                    self.assertTrue(await pilot.click(send_button))
                    await settle(pilot, lambda: pane.editor.query_one(".json_status").has_class("error"))
                    self.assertTrue(pane.editor.query_one(".json_status").has_class("error"))
                    self.assertEqual(service.db.sender_request(first["id"]), before)
                    self.assertEqual(len(sent), 1)
                    self.assertFalse(send_button.disabled)

                    area.load('{"operation":"sendBroadcast","intent":{"action":"send.immediately"}}')
                    await pilot.pause()
                    self.assertEqual(service.db.sender_request(first["id"]), before)
                    self.assertFalse(send_button.disabled)
                    self.assertTrue(await pilot.click(send_button))
                    await settle(pilot, lambda: len(sent) == 2)
                    self.assertEqual(sent[1]["intent"]["action"], "send.immediately")

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
                await pilot.press("ctrl+t")
                await pilot.pause()
                self.assertFalse(app.query("#btn_history_view"))  # A shortcut only, shown in the footer.
                self.assertIn('"hook": "sendOrderedBroadcast()"', shown())  # Shown for reading only...
                self.assertIn('"operation": "sendOrderedBroadcast"', shown())  # The hooked call itself.
                self.assertNotIn("hook", saved[0]["request"])  # ...To Sender converts it away.
                self.assertIn('"action": "test.PING"', shown())
                self.assertNotIn("[HOOK]", shown())
                await pilot.press("ctrl+t")
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

                # startActivity without NEW_TASK arrives as a draft to repair.
                app._history_selected_entry = {"id": 9, "method": "startActivity", "intent": intent}
                await pilot.press("ctrl+r")
                await pilot.pause(0.6)
                self.assertEqual(len(app.db.sender_requests()), 3)
                self.assertEqual(app.db.sender_request(pane._selected_id)["request"], {})  # Nothing invented.
                self.assertIn('"operation": "startActivity"', pane.editor.area.text)
                self.assertIn('"action": "test.PING"', pane.editor.area.text)
                self.assertTrue(pane.editor_dirty())
                row = app.db.sender_request(pane._selected_id)
                self.assertIn("FLAG_ACTIVITY_NEW_TASK", app.db.sender_draft(row["id"], row["revision"])[1])

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

                # Info app sends a component the same way: named with the next number, not the component.
                await pilot.click("#--content-tab-tab_info")
                await pilot.pause(0.3)
                app.query_one("#info_views", TabbedContent).active = "info_view_components"
                await pilot.pause(0.3)
                button = app.query_one("#info_to_sender")
                self.assertEqual(str(button.label), "To Sender")
                self.assertTrue(button.disabled)  # No component selected.
                app._app_info = {"identity": {"package": "test.app"},
                                 "components": [{"name": "test.app.Receiver", "type": "receiver"},
                                                {"name": "test.app.Two", "type": "provider", "authority": "a;b"}]}
                app._info_selected_component = "test.app.Two"
                app._refresh_info_to_sender()
                self.assertTrue(button.disabled)  # Two authorities: Sender cannot choose one.
                self.assertIsNone(app.check_action("send_to_sender", ()))
                app._info_selected_component = "test.app.Receiver"
                app._refresh_info_to_sender()
                self.assertFalse(button.disabled)
                self.assertTrue(app.check_action("send_to_sender", ()))
                await pilot.press("ctrl+r")  # Ctrl+R is To Sender here too; Refresh is Ctrl+G.
                await pilot.pause()
                newest = app.db.sender_request(pane._selected_id)
                self.assertEqual((newest["name"], newest["request"]["intent"]["component"]),
                                 ("5", "test.app/test.app.Receiver"))

    async def test_sender_tabs_and_controls_fit_and_do_not_change_other_tabs(self):
        for theme in ("noxen-dark", "noxen-light"):
            with self.subTest(theme=theme), tempfile.TemporaryDirectory() as directory:
                app = NoxenApp(SimpleNamespace(project=None, new_project=directory + "/sender", skip_device_scan=True))
                async with app.run_test(size=(120, 40)) as pilot:
                    app.theme = theme
                    # Saved before Sender is shown: no empty request is added next to them.
                    first = app.sender_service.save_request("B", {"operation": "sendBroadcast", "intent": {}})
                    app.sender_service.save_request("A", {"operation": "sendBroadcast", "intent": {}})
                    app.query_one("#main_tabs", TabbedContent).active = "tab_sender"
                    await pilot.pause()
                    pane = app.query_one(SenderPane)
                    for identifier in ("sender_connect", "sender_disconnect", "sender_send", "sender_new"):
                        self.assertLessEqual(pane.query_one(f"#{identifier}").region.right, pane.region.right)
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
                    await settle(pilot, lambda: isinstance(app.screen, SenderTabMenu)
                                 and isinstance(app.focused, OptionList) and app.focused.screen is app.screen)
                    menu = app.screen.query_one(OptionList)
                    menu.highlighted = next(
                        i for i in range(menu.option_count) if menu.get_option_at_index(i).id == "close"
                    )
                    await pilot.press("enter")
                    await settle(pilot, lambda: [str(tab.label) for tab in pane.query(RequestTab)] == ["A"])
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

                    for terminal_width in (72, 60):
                        await pilot.resize_terminal(terminal_width, 36)
                        await pilot.pause()
                        device = pane.query_one("#sender_device")
                        application = pane.query_one("#sender_app")
                        refresh = pane.query_one("#sender_refresh")
                        disconnect = pane.query_one("#sender_disconnect")
                        self.assertEqual(device.region.height, 3)
                        self.assertEqual(application.region.height, 3)
                        self.assertEqual(refresh.region.y == device.region.y, terminal_width == 72)
                        self.assertLessEqual(disconnect.region.right, pane.region.right)
