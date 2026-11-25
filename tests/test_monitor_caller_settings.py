import itertools
import json
import tempfile
import unittest
from types import SimpleNamespace

from textual.app import App
from textual.widgets import Input, Select, Switch

from noxen.app import NoxenApp
from noxen.monitor import PROFILE_FORMAT_VERSION, effective_hook, enabled_hooks, load_profiles, validate_profiles
from noxen.monitor_ui import MonitorDialog, MonitorPane, ProfileCallerDialog


class CallerSettingsTests(unittest.TestCase):
    def test_configuration_matrix_and_roundtrip(self):
        for inherit, stack, profile_filter, local_filter, profile_on, hook_on in itertools.product((False, True), repeat=6):
            for depth in (16, 32, 64):
                for mode in ('direct', 'anywhere'):
                    with self.subTest(inherit=inherit, stack=stack, profile_filter=profile_filter,
                                      local_filter=local_filter, profile_on=profile_on, hook_on=hook_on,
                                      depth=depth, mode=mode):
                        profile = {
                            'id': 'test', 'name': 'Test', 'enabled': profile_on,
                            'callerSettings': {'callerFilter': 'profile.*' if profile_filter else '',
                                               'callerMatch': mode, 'stackDepth': depth},
                            'hooks': [{'class': 'Test', 'method': 'run', 'args': [], 'enabled': hook_on,
                                       'captureStack': stack, 'useProfileCaller': inherit,
                                       'callerFilter': 'local.*' if local_filter else '',
                                       'callerMatch': 'direct', 'stackDepth': 16}],
                        }
                        profiles = validate_profiles([profile])
                        actual = effective_hook(profiles[0], profiles[0]['hooks'][0])
                        expected_stack = stack or (inherit and profile_filter)
                        self.assertEqual(actual['captureStack'], expected_stack)
                        expected_filter = ('profile.*' if profile_filter else '') if inherit else ('local.*' if local_filter and stack else '')
                        self.assertEqual(actual.get('callerFilter', ''), expected_filter)
                        self.assertEqual(actual.get('stackDepth', 16), depth if inherit else 16)
                        self.assertEqual(len(enabled_hooks(profiles)), int(profile_on and hook_on))
                        restored, error = load_profiles(json.dumps({'version': PROFILE_FORMAT_VERSION, 'profiles': profiles}))
                        self.assertIsNone(error)
                        self.assertEqual(restored, profiles)


class CallerEditorTests(unittest.IsolatedAsyncioTestCase):
    async def test_profile_caller_settings_can_be_disabled_without_selecting_a_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            path = directory + "/caller.noxen"
            settings = {"callerFilter": "app.*", "callerMatch": "direct", "stackDepth": 16}
            other = {"callerFilter": "other.*", "callerMatch": "anywhere", "stackDepth": 32}
            profiles = [
                {"id": "first", "name": "First", "enabled": False, "hooks": [], "callerSettings": settings},
                {"id": "second", "name": "Second", "enabled": False, "hooks": [], "callerSettings": settings},
                {"id": "third", "name": "Third", "enabled": False, "hooks": [], "callerSettings": other},
            ]
            app = NoxenApp(SimpleNamespace(project=None, new_project=path, skip_device_scan=True))
            app.db.set_info("monitor_profiles", json.dumps({"version": PROFILE_FORMAT_VERSION, "profiles": profiles}))
            async with app.run_test(size=(100, 40)) as pilot:
                pane = app.query_one(MonitorPane)
                pane.run_profile_action("first", "caller_settings", None)
                await pilot.pause()
                self.assertIsInstance(app.screen, ProfileCallerDialog)
                self.assertTrue(app.screen.query_one("#caller_profile_0", Switch).value)
                self.assertTrue(app.screen.query_one("#caller_profile_1", Switch).value)
                self.assertFalse(app.screen.query_one("#caller_profile_2", Switch).value)
                app.screen.query_one("#caller_profile_0", Switch).value = False
                app.screen.query_one("#caller_profile_1", Switch).value = False
                await pilot.click("#monitor_save")
                await pilot.pause()
                self.assertNotIn("callerSettings", pane.profiles[0])
                self.assertNotIn("callerSettings", pane.profiles[1])
                self.assertEqual(pane.profiles[2]["callerSettings"], other)
            app.db.close()
            reopened = NoxenApp(SimpleNamespace(project=path, new_project=None, skip_device_scan=True))
            async with reopened.run_test(size=(100, 40)):
                restored = reopened.query_one(MonitorPane).profiles
                self.assertNotIn("callerSettings", restored[0])
                self.assertNotIn("callerSettings", restored[1])
                self.assertEqual(restored[2]["callerSettings"], other)
            reopened.db.close()

    async def test_initial_editor_state_matches_effective_configuration(self):
        app = App()
        async with app.run_test(size=(100, 40)) as pilot:
            for inherit, stack, profile_filter, local_filter in itertools.product((False, True), repeat=4):
                hook = {'class': 'Test', 'method': 'run', 'args': [], 'useProfileCaller': inherit,
                        'captureStack': stack, 'callerFilter': 'local.*' if local_filter else ''}
                settings = {'callerFilter': 'profile.*' if profile_filter else '', 'stackDepth': 32}
                expected = effective_hook({'callerSettings': settings}, hook)
                app.push_screen(MonitorDialog(hook=hook, profile_caller=settings))
                await pilot.pause()
                with self.subTest(inherit=inherit, stack=stack, profile_filter=profile_filter, local_filter=local_filter):
                    screen = app.screen
                    capture = screen.query_one('#captureStack', Switch)
                    field = screen.query_one('#monitor_caller', Input)
                    self.assertEqual(capture.value, expected['captureStack'])
                    self.assertEqual(capture.disabled, inherit and profile_filter)
                    self.assertEqual(field.disabled, inherit or not expected['captureStack'])
                    self.assertEqual(field.value, settings['callerFilter'] if inherit else hook['callerFilter'])
                await pilot.click('#monitor_cancel')

    async def test_local_settings_survive_inheritance_and_reopen(self):
        hook = {'class': 'Test', 'method': 'run', 'args': [], 'useProfileCaller': False,
                'captureStack': False, 'callerFilter': 'local.*', 'callerMatch': 'direct', 'stackDepth': 32}
        profile = {'callerFilter': 'profile.*', 'callerMatch': 'anywhere', 'stackDepth': 64}
        saved = []
        app = App()
        async with app.run_test(size=(100, 40)) as pilot:
            app.push_screen(MonitorDialog(hook=hook, profile_caller=profile), saved.append)
            await pilot.pause()
            screen = app.screen
            stack = screen.query_one('#captureStack', Switch)
            inherit = screen.query_one('#monitor_inherit_caller', Switch)
            field = screen.query_one('#monitor_caller', Input)
            self.assertTrue(field.disabled)
            stack.value = True
            await pilot.pause()
            self.assertFalse(field.disabled)
            field.value = 'edited.*'
            stack.value = False
            await pilot.pause()
            inherit.value = True
            await pilot.pause()
            self.assertTrue(stack.value)
            self.assertTrue(stack.disabled)
            self.assertEqual(field.value, 'profile.*')
            self.assertEqual(screen.query_one('#monitor_stack_depth', Select).value, 64)
            inherit.value = False
            await pilot.pause()
            self.assertFalse(stack.value)
            self.assertFalse(stack.disabled)
            self.assertEqual(field.value, 'edited.*')
            self.assertEqual(screen.query_one('#monitor_stack_depth', Select).value, 32)
            inherit.value = True
            await pilot.pause()
            await pilot.click('#monitor_save')
            self.assertFalse(saved[0]['captureStack'])
            self.assertEqual(saved[0]['callerFilter'], 'edited.*')
            self.assertTrue(effective_hook({'callerSettings': profile}, saved[0])['captureStack'])
            self.assertFalse(effective_hook({'callerSettings': {}}, saved[0])['captureStack'])
            app.push_screen(MonitorDialog(hook=saved[0], profile_caller={}), saved.append)
            await pilot.pause()
            self.assertFalse(app.screen.query_one('#captureStack', Switch).value)
            app.screen.query_one('#monitor_inherit_caller', Switch).value = False
            await pilot.pause()
            self.assertEqual(app.screen.query_one('#monitor_caller', Input).value, 'edited.*')
            self.assertFalse(app.screen.query_one('#captureStack', Switch).value)
