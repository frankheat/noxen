import asyncio
import os
import tempfile
import unittest
from types import SimpleNamespace

from noxen.app import NoxenApp
from noxen.settings import load_settings, settings_file_path


def project_args_without_device_scan(path: str) -> SimpleNamespace:
    return SimpleNamespace(
        project=None,
        new_project=path,
        skip_device_scan=True,
    )


class CommandBarVisibilityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        asyncio.get_running_loop().slow_callback_duration = 1.0

    async def test_intercept_action_buttons_use_state_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                app = NoxenApp(project_args_without_device_scan(os.path.join(tmp, "missing.noxen")))
                async with app.run_test(size=(100, 32)):
                    intercept = app.query_one("#intercept_toggle")
                    forward = app.query_one("#btn_forward")
                    drop = app.query_one("#btn_drop")
                    edit = app.query_one("#btn_edit")

                    self.assertEqual(intercept.variant, "default")
                    self.assertIn("intercept-on", intercept.classes)

                    app.set_intercept_state(True)
                    self.assertIn("forward-ready", forward.classes)
                    self.assertIn("drop-ready", drop.classes)
                    self.assertIn("edit-ready", edit.classes)

                    app.set_intercept_state(False)
                    self.assertNotIn("forward-ready", forward.classes)
                    self.assertNotIn("drop-ready", drop.classes)
                    self.assertNotIn("edit-ready", edit.classes)
            finally:
                os.chdir(previous_cwd)

    async def test_ctrl_b_toggles_intercept_and_history_command_bars_independently(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous_cwd = os.getcwd()
            previous_xdg = os.environ.get("XDG_CONFIG_HOME")
            os.environ["XDG_CONFIG_HOME"] = tmp
            os.chdir(tmp)
            try:
                app = NoxenApp(project_args_without_device_scan(os.path.join(tmp, "missing.noxen")))
                async with app.run_test(size=(100, 32)) as pilot:
                    tabs = app.query_one("#main_tabs")

                    self.assertFalse(app.check_action("toggle_command_bar", ()))

                    tabs.active = "tab_intercept"
                    await pilot.pause()
                    self.assertTrue(app.check_action("toggle_command_bar", ()))
                    await pilot.press("ctrl+b")
                    await pilot.pause()

                    self.assertFalse(app.query_one("#intercept_cmd_output").display)
                    self.assertFalse(app.query_one("#intercept_input_wrapper").display)
                    self.assertTrue(app._history_command_bar_visible)

                    await pilot.press("ctrl+b")
                    await pilot.pause()
                    self.assertTrue(app.query_one("#intercept_cmd_output").display)

                    tabs.active = "tab_history"
                    await pilot.pause()
                    self.assertTrue(app.check_action("toggle_command_bar", ()))
                    await pilot.press("ctrl+b")
                    await pilot.pause()

                    self.assertFalse(app.query_one("#history_bar_container").display)
                    self.assertTrue(app.query_one("#intercept_cmd_output").display)

                saved = load_settings(settings_file_path())
                self.assertTrue(saved["intercept_command_bar"])
                self.assertFalse(saved["history_command_bar"])
            finally:
                os.chdir(previous_cwd)
                if previous_xdg is None:
                    os.environ.pop("XDG_CONFIG_HOME", None)
                else:
                    os.environ["XDG_CONFIG_HOME"] = previous_xdg


if __name__ == "__main__":
    unittest.main()
