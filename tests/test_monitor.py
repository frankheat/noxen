import asyncio
import json
import os
import sqlite3
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from textual.widgets import Input, DataTable, Label, Switch, TabbedContent, TextArea
from noxen.app import NoxenApp
from noxen.db import ProjectDB
from noxen.monitor import (PROFILE_FORMAT_VERSION, argument_type, default_profiles,
                           enabled_hooks, event_detail, load_profiles, render_event_detail, signature,
                           validate_hook, validate_profiles)
from noxen.monitor_ui import ALL_HOOKS_ROW, MonitorPane
from tests.ui_test_case import IsolatedAppTestCase


async def wait_until(predicate):
    async def poll():
        while not predicate():
            await asyncio.sleep(0.02)

    await asyncio.wait_for(poll(), timeout=5)


class MonitorRecordingTests(IsolatedAppTestCase):
    async def test_quit_retries_last_batch_and_reopened_project_can_search_it(self):
        def event(event_id, method):
            return {"id": event_id, "time": 1, "profiles": ["Test"], "method": method, "outcome": "returned"}

        def batch(*events, dropped=0):
            return {"noxenEvent": "monitor_batch", "events": list(events), "dropped": dropped}

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "recorded.noxen")
            args = SimpleNamespace(project=None, new_project=path, skip_device_scan=True)
            app = NoxenApp(args)
            app.db.set_info("monitor_recording_enabled", "0")
            app.db.save_monitor_batch("legacy", "2026-01-01T00:00:00+00:00",
                                      [dict(event(1, "oldCall"), session=1)], 2, 1, "open")
            app.db.save_intent({"timestamp": "2026-01-01 00:00:00"})
            async with app.run_test(size=(100, 35)) as pilot:
                await pilot.click("#--content-tab-tab_monitor")
                pane = app.query_one(MonitorPane)
                await wait_until(lambda: [e["method"] for e in pane.events] == ["oldCall"])

                session = SimpleNamespace(
                    stop_monitor=lambda: batch(event(2, "finalCall"), dropped=7), cleanup=lambda: None,
                )
                app.frida_session = session
                pane.begin_session(session, "dev.noxen.playground")
                with patch.object(app.db, "save_monitor_batch", side_effect=sqlite3.OperationalError("disk full")):
                    pane.receive(session, batch(event(1, "firstCall")))
                    await pilot.press("ctrl+q")
                    for _ in range(20):
                        if app.screen.query("#recording_cancel"):
                            break
                        await pilot.pause(0.05)
                    self.assertIn("disk full", str(app.screen.query_one("#recording_message").render()))
                app.screen.dismiss(False)
                for _ in range(20):
                    if pane.recording is None:
                        break
                    await asyncio.sleep(0.05)
                self.assertIsNone(pane.recording)

            db = ProjectDB(path)
            db.open_existing()
            self.assertEqual(db.monitor_event_summary(), (9, 1, 1))
            events, has_older, latest_id = db.monitor_event_page("", None, 200)
            self.assertEqual([e["method"] for e in events], ["oldCall", "firstCall", "finalCall"])
            self.assertFalse(has_older)
            self.assertEqual(latest_id, 3)
            db.close()

            reopened = NoxenApp(SimpleNamespace(project=path, new_project=None, skip_device_scan=True))
            async with reopened.run_test(size=(100, 35)) as pilot:
                await pilot.click("#--content-tab-tab_monitor")
                pane = reopened.query_one(MonitorPane)
                await wait_until(lambda: len(pane.events) == 3)
                table = reopened.query_one("#monitor_events", DataTable)
                self.assertEqual([table.get_row_at(i)[0] for i in range(table.row_count)], [3, 2, 1])
                await pilot.click("#monitor_events", offset=(2, 1))
                await wait_until(lambda: table.columns["id"].label.plain == "ID ↑")
                await pilot.click("#monitor_events", offset=(2, 1))
                await wait_until(lambda: table.columns["id"].label.plain == "ID ↓")
                self.assertEqual([table.get_row_at(i)[0] for i in range(table.row_count)], [3, 2, 1])
                self.assertTrue(pane.status_text.startswith("9 lost during capture"))
                reopened.query_one("#monitor_search", Input).value = "finalcall"
                await wait_until(lambda: [e["method"] for e in pane.events] == ["finalCall"])
                self.assertEqual(table.get_row_at(0)[0], 3)
                await pilot.click("#--content-tab-monitor_profiles_view")
                self.assertFalse(any(key.key == "ctrl+l" for key in reopened.query("FooterKey")))
                await pilot.press("ctrl+l")
                self.assertEqual(table.row_count, 1)
                await pilot.click("#--content-tab-monitor_events_view")
                self.assertTrue(any(key.key == "ctrl+l" for key in reopened.query("FooterKey")))
                reopened.query_one("#monitor_search", Input).focus()
                await pilot.press("ctrl+l")
                await wait_until(lambda: not pane.events)
                self.assertFalse(reopened.query_one("#monitor_status").display)
            db = ProjectDB(path)
            self.assertEqual(len(db.open_existing()), 1)
            self.assertEqual(db.monitor_event_summary(), (0, 0, 0))
            self.assertEqual(db.monitor_event_page("", None, 1), ([], False, 0))
            db.close()


class MonitorModelTests(unittest.TestCase):
    def test_event_detail_dims_types_and_keeps_captured_text_literal(self):
        event = {
            "method": "getIntent",
            "types": ["android.content.Intent"],
            "arguments": [{"type": "android.content.Intent", "opaque": True}],
            "result": {"type": "java.lang.String", "value": "[bold]:cd:[/bold]"},
        }
        detail = render_event_detail(event)
        spans = [(detail.plain[span.start:span.end], span.style) for span in detail.spans]
        self.assertIn(("[CALL]", "bold"), spans)
        self.assertIn(("[android.content.Intent]", "dim"), spans)
        self.assertIn(("[java.lang.String]", "dim"), spans)
        self.assertIn('"[bold]:cd:[/bold]"', detail.plain)
        self.assertNotIn(('"[bold]:cd:[/bold]"', "dim"), spans)

    def test_validation_and_roundtrip(self):
        profiles = default_profiles()
        self.assertEqual(load_profiles(json.dumps(profiles[:1])), (profiles, None))
        version_one = {"version": 1, "profiles": profiles[:1]}
        self.assertEqual(load_profiles(json.dumps(version_one)), ([profiles[0], *profiles[2:]], None))
        version_two = {"version": 2, "profiles": profiles[:2]}
        self.assertEqual(load_profiles(json.dumps(version_two)), ([*profiles[:2], *profiles[3:]], None))
        version_three = {"version": 3, "profiles": profiles[:3]}
        self.assertEqual(load_profiles(json.dumps(version_three)), ([*profiles[:3], *profiles[4:]], None))
        version_four = {"version": 4, "profiles": profiles[:4]}
        self.assertEqual(load_profiles(json.dumps(version_four)), ([*profiles[:4], *profiles[5:]], None))
        version_five = {"version": 5, "profiles": profiles[:5]}
        self.assertEqual(load_profiles(json.dumps(version_five)), ([*profiles[:5], *profiles[6:]], None))
        version_six = {"version": 6, "profiles": profiles[:6]}
        self.assertEqual(load_profiles(json.dumps(version_six)), ([*profiles[:6], *profiles[7:]], None))
        version_seven = {"version": 7, "profiles": profiles[:7]}
        self.assertEqual(load_profiles(json.dumps(version_seven)), ([*profiles[:7], profiles[8]], None))
        current = {"version": PROFILE_FORMAT_VERSION, "profiles": profiles[:1]}
        self.assertEqual(load_profiles(json.dumps(current)), (profiles[:1], None))
        self.assertEqual(enabled_hooks(profiles), [])
        profiles[0]['enabled'] = True
        self.assertEqual(len(enabled_hooks(profiles)), 8)
        self.assertEqual(argument_type('java.lang.String[][]'), '[[Ljava.lang.String;')
        self.assertEqual(argument_type('int[]'), '[I')
        for value in ('void', '', 'java.lang.String...', 'void[]'):
            with self.assertRaises(ValueError):
                argument_type(value)
        profiles[0]['hooks'].append(profiles[0]['hooks'][0])
        with self.assertRaises(ValueError):
            validate_profiles(profiles)
        for raw in ('[]x', 'null', '{}', '[{}]'):
            self.assertIsNotNone(load_profiles(raw)[1])

    def test_uri_grant_detail_names_the_destination_and_decodes_flags(self):
        detail = event_detail({
            "class": "android.app.ContextImpl",
            "method": "grantUriPermission",
            "types": ["java.lang.String", "android.net.Uri", "int"],
            "arguments": [
                {"type": "java.lang.String", "value": "dev.example.target"},
                {"type": "android.net.Uri", "value": "content://example/report"},
                {"type": "int", "value": 0x81},
            ],
        })
        self.assertIn('Target package [java.lang.String] : "dev.example.target"', detail)
        self.assertIn("Mode flags [int] : 0x00000081 (READ | PREFIX)", detail)

    def test_android_log_throwable_overload_and_println_priority(self):
        detail = event_detail({
            "class": "android.util.Log",
            "method": "w",
            "types": ["java.lang.String", "java.lang.Throwable"],
            "arguments": [
                {"type": "java.lang.String", "value": "Example"},
                {"type": "java.lang.IllegalStateException", "opaque": True},
            ],
        })
        self.assertIn("Level   : WARN", detail)
        self.assertIn("Throwable [java.lang.IllegalStateException] : opaque object", detail)
        self.assertNotIn("Message [", detail)
        println = event_detail({
            "class": "android.util.Log",
            "method": "println",
            "types": ["int", "java.lang.String", "java.lang.String"],
            "arguments": [
                {"type": "int", "value": 5},
                {"type": "java.lang.String", "value": "Example"},
                {"type": "java.lang.String", "value": "message"},
            ],
        })
        self.assertIn("Priority [int] : 5 (WARN)", println)


class MonitorUITests(IsolatedAppTestCase):
    async def test_restore_only_missing_hooks_and_reopen_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "restore.noxen")
            app = NoxenApp(SimpleNamespace(project=None, new_project=path, skip_device_scan=True))
            profiles = default_profiles()
            log = next(p for p in profiles if p["id"] == "android-log")
            defaults = {signature(hook) for hook in log["hooks"]}
            log["enabled"] = True
            log["hooks"][0]["captureStack"] = True
            log["hooks"].append(validate_hook({"class": "com.example.Test", "method": "record"}))
            app.db.set_info("monitor_profiles", json.dumps({"version": PROFILE_FORMAT_VERSION, "profiles": profiles}))

            async with app.run_test(size=(80, 24)) as pilot:
                app.query_one("#main_tabs", TabbedContent).active = "tab_monitor"
                await pilot.pause()
                await pilot.click("#--content-tab-monitor_profiles_view")
                profiles = app.query_one("#monitor_profiles", DataTable)
                profiles.move_cursor(row=profiles.get_row_index("android-log"))
                await pilot.pause()
                pane = app.query_one(MonitorPane)
                group = app.query_one("#monitor_profile_actions_group")
                button = app.query_one("#monitor_profile_actions")
                self.assertTrue(group.content_region.contains_region(button.region))
                await pilot.click("#monitor_profile_actions")
                menu = app.screen.query_one("#monitor_actions_menu")
                self.assertEqual(menu.option_count, 3)
                self.assertEqual(menu.region.y, app.query_one("#monitor_profile_actions").region.bottom)
                self.assertEqual(app.screen.styles.background.a, 0)
                await pilot.press("escape")
                table = app.query_one("#monitor_hooks", DataTable)
                table.move_cursor(row=1)
                restore_button = app.query_one("#monitor_restore")
                self.assertFalse(restore_button.display)
                selected = signature(pane.profile()["hooks"][1])
                await pilot.click("#monitor_hooks", offset=(17, 0))
                self.assertEqual(table.get_row_at(table.cursor_row)[1].plain, selected)
                for _ in range(2):
                    await pilot.click("#monitor_remove")
                before = pane.profile()["hooks"][:]
                self.assertEqual(len(before), 14)
                self.assertNotIn(selected, {signature(hook) for hook in before})
                await pilot.click("#monitor_profile_actions")
                self.assertEqual(app.screen.query_one("#monitor_actions_menu").option_count, 3)
                await pilot.press("escape")
                self.assertTrue(restore_button.display)
                self.assertEqual(str(restore_button.label), "Restore missing hooks (2)")
                actions = app.query_one("#monitor_hook_actions")
                self.assertTrue(actions.content_region.contains_region(restore_button.region))
                self.assertGreater(restore_button.region.y, app.query_one("#monitor_remove").region.y)
                await pilot.resize_terminal(120, 24)
                self.assertTrue(actions.content_region.contains_region(restore_button.region))
                self.assertEqual(restore_button.region.y, app.query_one("#monitor_remove").region.y)
                await pilot.resize_terminal(80, 24)
                await pilot.click("#monitor_restore")
                message = app.screen.query_one("#monitor_restore_message", Label)
                self.assertIn("Add 2 missing default hooks", str(message.render()))
                await pilot.click("#monitor_restore_cancel")
                self.assertEqual(pane.profile()["hooks"], before)

                await pilot.click("#monitor_restore")
                await pilot.click("#monitor_restore_confirm")
                await pilot.pause()
                restored = pane.profile()
                self.assertEqual(restored["hooks"][:len(before)], before)
                self.assertTrue(defaults.issubset({signature(h) for h in restored["hooks"]}))
                self.assertEqual(len(restored["hooks"]), 16)
                self.assertTrue(restored["enabled"])
                self.assertFalse(restore_button.display)

                profiles.move_cursor(row=profiles.get_row_index("java-network"))
                await pilot.pause()
                await pilot.click("#monitor_profile_actions")
                await pilot.press("end", "enter")
                self.assertNotIn("java-network", profiles.rows)

                profiles.move_cursor(row=profiles.get_row_index(ALL_HOOKS_ROW))
                await pilot.pause()
                await pilot.click("#monitor_profile_actions")
                menu = app.screen.query_one("#monitor_actions_menu")
                self.assertEqual(str(menu.get_option("restore_profiles").prompt), "Restore profiles (1)")
                await pilot.press("home", "enter")
                menu = app.screen.query_one("#monitor_actions_menu")
                self.assertEqual(str(menu.get_option("java-network").prompt), "Java Network")
                await pilot.press("home", "enter")
                restored_network = next(p for p in default_profiles() if p["id"] == "java-network")
                self.assertEqual(pane.profile(), restored_network)
                self.assertFalse(pane.profile()["enabled"])

            app.db.close()
            reopened = NoxenApp(SimpleNamespace(project=path, new_project=None, skip_device_scan=True))
            async with reopened.run_test(size=(80, 24)):
                profiles = reopened.query_one(MonitorPane).profiles
                self.assertEqual(next(p for p in profiles if p["id"] == "android-log"), restored)
                self.assertEqual(next(p for p in profiles if p["id"] == "java-network"), restored_network)
            reopened.db.close()

    async def test_profile_hook_dialog_persistence_and_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = SimpleNamespace(project=None, new_project=os.path.join(tmp, 'monitor.noxen'), skip_device_scan=True)
            app = NoxenApp(args)
            async with app.run_test(size=(80, 24)) as pilot:
                app.query_one('#main_tabs', TabbedContent).active = 'tab_monitor'
                pane = app.query_one(MonitorPane)
                await pilot.pause()
                await pilot.click("#--content-tab-monitor_profiles_view")
                self.assertEqual(app._active_tab, "tab_monitor")
                hook_actions = app.query_one("#monitor_hook_actions")
                for button in hook_actions.query("Button"):
                    if button.display:
                        self.assertTrue(hook_actions.content_region.contains_region(button.region))
                profiles = app.query_one("#monitor_profiles", DataTable)
                self.assertEqual(profiles.row_count, len(default_profiles()) + 1)
                profiles.scroll_home(animate=False, immediate=True)
                await pilot.pause()
                self.assertEqual(profiles.get_row("content-provider")[0].plain, "○")
                first_row_y = profiles.styles.gutter.top + profiles.header_height
                provider_y = profiles.get_row_index("content-provider") + first_row_y
                grants_y = profiles.get_row_index("uri-grants") + first_row_y
                await pilot.click("#monitor_profiles", offset=(10, provider_y))
                self.assertEqual(pane.profile()["id"], "content-provider")
                self.assertEqual(profiles.get_row("content-provider")[0].plain, "○")
                await pilot.click("#monitor_profiles", offset=(profiles.virtual_size.width, provider_y))
                self.assertEqual(profiles.get_row("content-provider")[0].plain, "○")
                await pilot.click("#monitor_profiles", offset=(2, grants_y))
                self.assertEqual(pane.profile()["id"], "uri-grants")
                self.assertEqual(profiles.get_row("uri-grants")[0].plain, "✓")
                await pilot.click("#monitor_profiles", offset=(2, grants_y))
                self.assertEqual(profiles.get_row("uri-grants")[0].plain, "○")
                await pilot.click("#monitor_profiles", offset=(10, provider_y))
                await pilot.press("space")
                self.assertEqual(profiles.get_row("content-provider")[0].plain, "✓")
                await pilot.click("#monitor_profile_actions")
                await pilot.click("#monitor_actions_menu", offset=(3, 1))
                self.assertEqual(profiles.get_row("content-provider")[0].plain, "○")
                self.assertEqual(pane.profile()["id"], "content-provider")
                await pilot.click("#monitor_profiles", offset=(10, first_row_y))
                self.assertEqual(pane.selected_profile, ALL_HOOKS_ROW)
                self.assertFalse(app.query_one("#monitor_profile_actions").display)
                self.assertFalse(app.query_one("#monitor_remove").display)
                self.assertFalse(app.query_one("#monitor_restore").display)
                self.assertTrue(app.query_one("#monitor_new").display)
                self.assertTrue(app.query_one("#monitor_hook_details").display)
                profile_panel = app.query_one("#monitor_profile_panel")
                hook_panel = app.query_one("#monitor_hook_panel")
                self.assertEqual(hook_panel.region.x - profile_panel.region.right, 1)
                self.assertTrue(profile_panel.region.contains_region(app.query_one("#monitor_new").region))
                self.assertTrue(hook_panel.region.contains_region(app.query_one("#monitor_hook_details").region))
                self.assertEqual(profile_panel.border_title, "Profiles")
                self.assertEqual(hook_panel.border_title, "Hooks")
                await pilot.press("space")
                self.assertFalse(any(p["enabled"] for p in pane.profiles))
                hooks = app.query_one("#monitor_hooks", DataTable)
                self.assertEqual(hooks.row_count, sum(len(p["hooks"]) for p in pane.profiles))
                provider_hook = len(pane.profiles[0]["hooks"])
                self.assertEqual(hooks.get_row_at(provider_hook)[0], "Disabled")
                self.assertEqual(hooks.get_row_at(provider_hook)[1].plain, "Content Provider")
                self.assertEqual(hooks.get_row_at(provider_hook)[2].plain, signature(pane.profiles[1]["hooks"][0]))
                hooks.focus()
                await pilot.pause()
                self.assertEqual(
                    profiles.get_component_styles("datatable--fixed-cursor").background,
                    profiles.get_component_styles("datatable--cursor").background,
                )
                await pilot.press("right")
                await pilot.pause(0.2)
                self.assertGreater(hooks.scroll_x, 0)
                await pilot.resize_terminal(300, 30)
                self.assertEqual(hooks.virtual_size.width, hooks.scrollable_content_region.width)
                await pilot.resize_terminal(80, 24)
                hooks.move_cursor(row=provider_hook)
                await pilot.click("#monitor_hook_details")
                details = app.screen.query_one(TextArea).text
                self.assertIn("android.content.ContentResolver.query(", details)
                self.assertIn("Profile: Content Provider", details)
                await pilot.press("escape")
                await pilot.click("#monitor_hooks", offset=(17, 0))
                profile_names = [hooks.get_row_at(i)[1].plain for i in range(hooks.row_count)]
                self.assertEqual(profile_names, sorted(profile_names, key=str.casefold))
                self.assertEqual(hooks.get_row_at(hooks.cursor_row)[1].plain, "Content Provider")
                await pilot.click("#monitor_hooks", offset=(17, 0))
                self.assertEqual([hooks.get_row_at(i)[1].plain for i in range(hooks.row_count)],
                                 sorted(profile_names, key=str.casefold, reverse=True))
                self.assertEqual(hooks.columns["profile"].label.plain, "Profile ↓")
                await pilot.click("#monitor_hooks", offset=(2, 0))
                self.assertEqual(hooks.columns["state"].label.plain, "State ↑")
                profiles.move_cursor(row=profiles.get_row_index("webview"))
                await pilot.pause()
                hooks = app.query_one('#monitor_hooks', DataTable)
                hooks.move_cursor(row=4)
                narrow_width = list(hooks.columns.values())[1].width
                await pilot.resize_terminal(140, 24)
                self.assertEqual(list(hooks.columns.values())[1].width, narrow_width + 60)
                self.assertEqual(hooks.cursor_row, 4)
                await pilot.resize_terminal(80, 24)
                self.assertEqual(list(hooks.columns.values())[1].width, narrow_width)
                await pilot.click('#monitor_hook_details')
                self.assertIn("android.webkit.WebView.loadDataWithBaseURL(", app.screen.query_one(TextArea).text)
                await pilot.press("escape")
                selected = hooks.get_row_at(hooks.cursor_row)[1].plain
                await pilot.click("#monitor_hooks", offset=(17, 0))
                methods = [hooks.get_row_at(i)[1].plain for i in range(hooks.row_count)]
                self.assertEqual(methods, sorted(methods, key=str.casefold))
                self.assertEqual(hooks.get_row_at(hooks.cursor_row)[1].plain, selected)
                await pilot.click("#monitor_edit")
                self.assertEqual(app.screen.query_one("#monitor_method", Input).value, "loadDataWithBaseURL")
                await pilot.click("#monitor_cancel")
                await pilot.click('#monitor_new')
                app.screen.query_one('#monitor_name', Input).value = 'My profile'
                await pilot.click('#monitor_save')
                await pilot.pause()
                self.assertEqual(pane.profile()['name'], 'My profile')
                await pilot.click('#monitor_add')
                self.assertTrue(app.screen.region.contains_region(app.screen.query_one('#monitor_save').region))
                app.screen.query_one('#monitor_class', Input).value = 'com.example.Test'
                app.screen.query_one('#monitor_method', Input).value = 'check'
                args_input = app.screen.query_one('#monitor_args', Input)
                args_input.value = 'java.lang.String, boolean'
                arguments = app.screen.query_one('#captureArguments', Switch)
                returns = app.screen.query_one('#captureReturn', Switch)
                stack = app.screen.query_one('#captureStack', Switch)
                self.assertEqual((arguments.value, returns.value, stack.value), (True, True, False))
                args_input.focus()
                await pilot.press("tab", "tab", "space", "tab", "space")
                self.assertEqual((arguments.value, returns.value, stack.value), (True, False, True))
                await pilot.click('#monitor_save')
                await pilot.pause()
                self.assertEqual(pane.profile()['hooks'][0]['args'], ['java.lang.String', 'boolean'])
                await pilot.click('#monitor_edit')
                self.assertEqual(
                    tuple(app.screen.query_one(f"#{key}", Switch).value
                          for key in ("captureArguments", "captureReturn", "captureStack")),
                    (True, False, True),
                )
                await pilot.click('#monitor_cancel')
                self.assertEqual(len(json.loads(app.db.get_info('monitor_profiles'))["profiles"]), 10)
                await pilot.click("#--content-tab-monitor_events_view")
                session = SimpleNamespace()
                pane.begin_session(session)
                pane.receive(session, {'noxenEvent': 'monitor_batch', 'events': [
                    {'id': 1, 'time': 1, 'profiles': ['My profile'], 'method': 'check', 'outcome': 'returned',
                     'arguments': [{'type': 'java.lang.String', 'value': '[bold]test\ntext'}]}], 'dropped': 3})
                pane.drain()
                events_table = app.query_one('#monitor_events', DataTable)
                await wait_until(lambda: events_table.row_count == 1)
                self.assertEqual(pane.lost, 3)
                app.query_one('#monitor_search', Input).value = 'absent'
                await wait_until(lambda: events_table.row_count == 0)
                app.query_one('#monitor_search', Input).value = 'test'
                await wait_until(lambda: events_table.row_count == 1)
                pane.receive(SimpleNamespace(), {'events': [{'id': 2}]})
                pane.drain()
                self.assertEqual(len(pane.events), 1)
                app.query_one('#monitor_search', Input).value = ''
                await pilot.pause()
                for start in range(2, 2018, 32):
                    pane.receive(session, {'noxenEvent': 'monitor_batch', 'events': [
                        {'id': i, 'time': i, 'profiles': ['Load test'], 'method': 'run',
                         'outcome': 'returned', 'arguments': []} for i in range(start, start + 32)], 'dropped': 0})
                pane.drain()
                await wait_until(lambda: bool(pane.events) and pane.events[0]["id"] == 2017)
                search = app.query_one("#monitor_search", Input)
                search.value = "no event matches this"
                await wait_until(lambda: not pane.events)
                search.value = ""
                await wait_until(lambda: len(pane.events) == 200)
                self.assertEqual(events_table.row_count, 200)
                events_table.scroll_to(y=events_table.max_scroll_y, animate=False, immediate=True)
                await wait_until(lambda: len(pane.events) == 400)
                self.assertEqual([e["_db_id"] for e in pane.events], list(range(2017, 1617, -1)))
                pane.receive(session, {'noxenEvent': 'monitor_status', 'revision': -1,
                    'statuses': [{'profile':'webview','index':0,'state':'Active','detail':''}]})
                pane.drain()
                self.assertEqual(pane.statuses, {})
                detail = app.query_one("#monitor_detail")
                self.assertTrue(pane.region.contains_region(detail.region))
                await pilot.pause()
                detail.scroll_end(animate=False, immediate=True)
                await pilot.pause()
                scroll_y = detail.scroll_y
                self.assertGreater(scroll_y, 0)
                selected = pane.selected
                top = events_table.scroll_offset.y
                top_event_id = events_table.get_row_at(top)[0]
                pane.receive(session, {'noxenEvent': 'monitor_batch', 'events': [
                    {'id': 2018, 'time': 2018, 'profiles': ['Load test'], 'method': 'run',
                     'outcome': 'returned', 'arguments': []}], 'dropped': 0})
                pane.drain()
                await wait_until(lambda: pane.events[0]["id"] == 2018)
                await pilot.pause()
                self.assertEqual(pane.selected, selected)
                self.assertEqual(detail.scroll_y, scroll_y)
                self.assertEqual(events_table.get_row_at(events_table.scroll_offset.y)[0], top_event_id)
                method_x = 2 + sum(column.get_render_width(events_table) for column in events_table.ordered_columns[:3])
                await pilot.click("#monitor_events", offset=(method_x, 1))
                await wait_until(lambda: events_table.columns["method"].label.plain == "Method ↑")
                self.assertEqual([event["_db_id"] for event in pane.events], list(range(1, 201)))
                events_table.scroll_to(y=events_table.max_scroll_y, animate=False, immediate=True)
                await wait_until(lambda: len(pane.events) == 400)
                self.assertEqual([event["_db_id"] for event in pane.events], list(range(1, 401)))
                await pilot.click("#monitor_events", offset=(method_x, 1))
                await wait_until(lambda: events_table.columns["method"].label.plain == "Method ↓")
                self.assertEqual([event["_db_id"] for event in pane.events], list(range(2018, 1818, -1)))
                events_table.move_cursor(row=10)
                await pilot.pause()
                selected = pane.selected
                pane.receive(session, {"noxenEvent": "monitor_batch", "events": [
                    {"id": 2019, "time": 2019, "method": "start", "outcome": "returned"},
                ]})
                pane.drain()
                await wait_until(lambda: pane.events[0]["_db_id"] == 2019)
                self.assertEqual(events_table.get_row_at(0)[0], 2019)
                self.assertEqual(pane.selected, selected)
