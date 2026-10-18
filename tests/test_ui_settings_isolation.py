import unittest
from types import SimpleNamespace
from unittest.mock import patch

from noxen.app import NoxenApp
from noxen.settings import DEFAULT_SETTINGS, load_settings, save_settings
from noxen import settings as settings_module
from tests.ui_test_case import IsolatedAppTestCase, SettingsIsolationMixin


class UISettingsIsolationTests(IsolatedAppTestCase):
    def test_startup_never_resolves_personal_settings_directory(self):
        with patch("noxen.settings.user_config_dir", side_effect=AssertionError("Personal settings accessed")):
            app = NoxenApp(SimpleNamespace(project=None,
                new_project=str(self.settings_path.parent / "session.noxen"), skip_device_scan=True))
            try:
                self.assertEqual(app._settings, DEFAULT_SETTINGS)
                self.assertFalse(self.settings_path.exists())
            finally:
                app.db.close()
    def test_settings_persistence_is_real_and_confined_to_the_test_directory(self):
        with patch("noxen.settings.user_config_dir", side_effect=AssertionError("Personal settings accessed")):
            settings = {**DEFAULT_SETTINGS, "intercept_command_bar": False, "history_command_bar": False}
            save_settings(settings)
            self.assertTrue(self.settings_path.is_file())
            self.assertEqual(load_settings(), settings)
            app = NoxenApp(SimpleNamespace(project=None,
                new_project=str(self.settings_path.parent / "session.noxen"), skip_device_scan=True))
            try:
                self.assertFalse(app._intercept_command_bar_visible)
                self.assertFalse(app._history_command_bar_visible)
            finally:
                app.db.close()


class SettingsFixtureCleanupTests(unittest.TestCase):
    def test_failed_test_restores_settings_path_and_next_test_starts_clean(self):
        original_path_function = settings_module.settings_file_path
        paths = []

        class Probe(SettingsIsolationMixin, unittest.TestCase):
            def runTest(self):
                paths.append(self.settings_path)
                if len(paths) == 1:
                    save_settings({"intercept_command_bar": False})
                    self.fail("Deliberate fixture cleanup check")
                self.assertEqual(load_settings(), DEFAULT_SETTINGS)

        first = unittest.TestResult()
        Probe().run(first)
        self.assertEqual(len(first.failures), 1)
        self.assertIs(settings_module.settings_file_path, original_path_function)
        self.assertFalse(paths[0].parent.exists())
        second = unittest.TestResult()
        Probe().run(second)
        self.assertTrue(second.wasSuccessful(), second.errors or second.failures)
        self.assertNotEqual(paths[0], paths[1])
        self.assertFalse(paths[1].parent.exists())
        self.assertIs(settings_module.settings_file_path, original_path_function)
