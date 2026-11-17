import asyncio
import tempfile
from pathlib import Path
from types import SimpleNamespace

from textual.widgets import Button

from tests.ui_test_case import IsolatedAppTestCase

from noxen.app import NoxenApp
from noxen.modals import ExtraKeyModal


class ExtraKeyTests(IsolatedAppTestCase):
    async def test_key_dialog_buttons_never_reverse_text_on_focus_or_press(self):
        asyncio.get_running_loop().slow_callback_duration = 1.0
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(
                new_project=str(Path(directory) / "buttons.noxen"), project=None, skip_device_scan=True,
            ))
            async with app.run_test(size=(100, 40)) as pilot:
                for theme in ("noxen-dark", "noxen-light"):
                    app.theme = theme
                    app.push_screen(ExtraKeyModal("original_key"))
                    await pilot.pause()
                    self.assertEqual([button.id for button in app.screen.query(Button)], ["extra_key_close"])
                    for selector in ("#extra_key_close",):
                        button = app.screen.query_one(selector)
                        await pilot.hover(selector)
                        button.focus()
                        await pilot.pause()
                        self.assertFalse(button.styles.text_style.reverse)
                        self.assertTrue(button.styles.text_style.bold)
                        focused = (button.styles.color, button.styles.background,
                                   button.styles.border, button.styles.text_style)
                        # Textual uses this class for the short pressed animation.
                        button.add_class("-active")
                        await pilot.pause()
                        self.assertEqual((button.styles.color, button.styles.background,
                                          button.styles.border, button.styles.text_style), focused)
                        self.assertEqual(button.styles.tint.a, 0)
                        button.remove_class("-active")
                        await pilot.mouse_down(selector)
                        await pilot.pause()
                        self.assertFalse(button.styles.text_style.reverse)
                        await pilot.mouse_up(selector)
                    await pilot.press("escape")
                    await pilot.pause()
