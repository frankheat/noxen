import asyncio
import json
import os
import sqlite3
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from textual.widgets import Input, DataTable, Label, Select, TabbedContent, TextArea
from noxen.app import NoxenApp
from noxen.db import ProjectDB
from noxen.monitor import (PROFILE_FORMAT_VERSION, argument_type, default_profiles,
                           enabled_hooks, event_detail, load_profiles, signature, validate_hook, validate_profiles)
from noxen.monitor_ui import MonitorPane
from tests.ui_test_case import IsolatedAppTestCase


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
            async with app.run_test(size=(100, 35)) as pilot:
                await pilot.click("#--content-tab-tab_monitor")
                pane = app.query_one(MonitorPane)
                self.assertFalse(pane.recording_enabled)
                await pilot.click("#monitor_record")
                await pilot.click("#recording_confirm")
                for _ in range(20):
                    if pane.recording_enabled:
                        break
                    await pilot.pause(0.05)
                self.assertTrue(pane.recording_enabled)

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
            recordings = db.monitor_recordings()
            self.assertEqual(len(recordings), 1)
            key, _, lost, unsaved, status = recordings[0]
            self.assertEqual((lost, unsaved, status), (7, 0, "complete"))
            events, has_older = db.monitor_recording_page(key, "", 0, 200)
            self.assertEqual([e["method"] for e in events], ["firstCall", "finalCall"])
            self.assertFalse(has_older)
            db.close()

            reopened = NoxenApp(SimpleNamespace(project=path, new_project=None, skip_device_scan=True))
            async with reopened.run_test(size=(100, 35)) as pilot:
                await pilot.click("#--content-tab-tab_monitor")
                pane = reopened.query_one(MonitorPane)
                self.assertTrue(pane.recording_enabled)
                self.assertFalse(pane.events)
                reopened.query_one("#monitor_recordings", Select).value = key
                reopened.query_one("#monitor_search", Input).value = "finalcall"
                for _ in range(20):
                    if [e["method"] for e in pane.archive_events] == ["finalCall"]:
                        break
                    await pilot.pause(0.05)
                self.assertEqual([e["method"] for e in pane.archive_events], ["finalCall"])


class MonitorModelTests(unittest.TestCase):
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
                controls = app.query_one("#monitor_restore_controls")
                self.assertFalse(controls.display)
                table = app.query_one("#monitor_hooks", DataTable)
                table.move_cursor(row=1)
                await pilot.click("#monitor_remove")
                await pilot.click("#monitor_remove")
                before = pane.profile()["hooks"][:]
                self.assertEqual(len(before), 14)
                self.assertTrue(controls.display)
                self.assertTrue(app.screen.region.contains_region(app.query_one("#monitor_restore").region))

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
                self.assertFalse(controls.display)

            app.db.close()
            reopened = NoxenApp(SimpleNamespace(project=path, new_project=None, skip_device_scan=True))
            async with reopened.run_test(size=(80, 24)):
                profiles = reopened.query_one(MonitorPane).profiles
                self.assertEqual(next(p for p in profiles if p["id"] == "android-log"), restored)
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
                profiles = app.query_one("#monitor_profiles", DataTable)
                self.assertEqual(profiles.row_count, len(default_profiles()))
                self.assertEqual(profiles.get_row("content-provider")[0], "–")
                await pilot.click("#monitor_profiles", offset=(10, 3))
                self.assertEqual(pane.profile()["id"], "content-provider")
                await pilot.press("space")
                self.assertEqual(profiles.get_row("content-provider")[0], "✓")
                await pilot.click("#monitor_toggle")
                self.assertEqual(profiles.get_row("content-provider")[0], "–")
                self.assertEqual(pane.profile()["id"], "content-provider")
                profiles.move_cursor(row=0)
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
                await pilot.click('#monitor_new')
                app.screen.query_one('#monitor_name', Input).value = 'My profile'
                await pilot.click('#monitor_save')
                await pilot.pause()
                self.assertEqual(pane.profile()['name'], 'My profile')
                await pilot.click('#monitor_add')
                self.assertTrue(app.screen.region.contains_region(app.screen.query_one('#monitor_save').region))
                app.screen.query_one('#monitor_class', Input).value = 'com.example.Test'
                app.screen.query_one('#monitor_method', Input).value = 'check'
                app.screen.query_one('#monitor_args', Input).value = 'java.lang.String, boolean'
                await pilot.click('#monitor_save')
                await pilot.pause()
                self.assertEqual(pane.profile()['hooks'][0]['args'], ['java.lang.String', 'boolean'])
                self.assertEqual(len(json.loads(app.db.get_info('monitor_profiles'))["profiles"]), 10)
                await pilot.click("#--content-tab-monitor_events_view")
                session = SimpleNamespace()
                pane.begin_session(session)
                pane.receive(session, {'noxenEvent': 'monitor_batch', 'events': [
                    {'id': 1, 'time': 1, 'profiles': ['My profile'], 'method': 'check', 'outcome': 'returned',
                     'arguments': [{'type': 'java.lang.String', 'value': '[bold]test\ntext'}]}], 'dropped': 3})
                pane.drain()
                self.assertEqual(app.query_one('#monitor_events', DataTable).row_count, 1)
                self.assertEqual(pane.lost, 3)
                app.query_one('#monitor_search', Input).value = 'absent'
                await pilot.pause()
                self.assertEqual(app.query_one('#monitor_events', DataTable).row_count, 0)
                app.query_one('#monitor_search', Input).value = 'test'
                await pilot.pause()
                self.assertEqual(app.query_one('#monitor_events', DataTable).row_count, 1)
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
                self.assertEqual(len(pane.events), 2000)
                self.assertEqual(pane.evicted, 17)
                self.assertEqual(app.query_one('#monitor_events', DataTable).row_count, 200)
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
                pane.receive(session, {'noxenEvent': 'monitor_batch', 'events': [
                    {'id': 2018, 'time': 2018, 'profiles': ['Load test'], 'method': 'run',
                     'outcome': 'returned', 'arguments': []}], 'dropped': 0})
                pane.drain()
                await pilot.pause()
                self.assertEqual(pane.selected, selected)
                self.assertEqual(detail.scroll_y, scroll_y)
