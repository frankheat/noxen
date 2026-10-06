import asyncio
import os
import tempfile
import unittest
from types import SimpleNamespace

from textual.widgets import Label

from noxen.app import NoxenApp
from noxen.commands import HELP_MENU
from noxen.modals import HelpModal


def project_args(path: str) -> SimpleNamespace:
    return SimpleNamespace(project=None, new_project=path, skip_device_scan=True)


class HelpModalTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        asyncio.get_running_loop().slow_callback_duration = 1.0

    async def test_commands_align_and_long_examples_stay_inside_dialog(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                app = NoxenApp(project_args(os.path.join(tmp, "help.noxen")))
                async with app.run_test(size=(120, 40)) as pilot:
                    app.push_screen(HelpModal(HELP_MENU))
                    await pilot.pause()
                    await pilot.pause()

                    dialog = app.screen.query_one("#help_dialog")
                    commands = list(app.screen.query(".help_command"))
                    descriptions = list(app.screen.query(".help_description"))

                    self.assertTrue(commands)
                    self.assertEqual(len({label.size.width for label in commands}), 1)
                    self.assertEqual(len({label.region.x for label in descriptions}), 1)
                    self.assertTrue(all(label.region.right <= dialog.content_region.right for label in descriptions))
                    rendered_commands = [label.render().plain for label in commands if isinstance(label, Label)]
                    self.assertIn("+x [type] <key> <value>", rendered_commands)
                    self.assertIn("string-list", rendered_commands)
            finally:
                os.chdir(previous_cwd)


if __name__ == "__main__":
    unittest.main()
