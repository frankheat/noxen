import json
import os
import tempfile
import unittest
from types import SimpleNamespace

from textual.widgets import Input, DataTable, TabbedContent, TextArea
from noxen.app import NoxenApp
from noxen.monitor import (argument_type, default_profiles, enabled_hooks,
                           load_profiles, validate_profiles)
from noxen.monitor_ui import MonitorPane
from tests.ui_test_case import IsolatedAppTestCase


class MonitorModelTests(unittest.TestCase):
    def test_validation_and_roundtrip(self):
        profiles = default_profiles()
        self.assertEqual(load_profiles(json.dumps(profiles)), (profiles, None))
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


class MonitorUITests(IsolatedAppTestCase):
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
                self.assertEqual(len(json.loads(app.db.get_info('monitor_profiles'))), 2)
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
