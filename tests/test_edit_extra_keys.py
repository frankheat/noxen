import asyncio
import copy
import tempfile
from pathlib import Path
from types import SimpleNamespace

from textual.widgets import Button, Input, TextArea

from tests.ui_test_case import IsolatedAppTestCase

from noxen.app import ExtraKeyLabel, NoxenApp
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

    async def test_wrapping_alignment_resize_and_readonly_full_key(self):
        asyncio.get_running_loop().slow_callback_duration = 1.0
        keys = ["short", "com.example.authentication.session_token." * 2, "x" * 10000,
                "[bold]literal[/bold]:cd:", "界" * 60, "a\nb\tc"]
        info = {"action": None, "data": None, "mimeType": None, "flags": 0,
                "categories": [], "extras": {
                    key: {"type": "java.lang.String", "value": "value"} for key in keys
                }}
        original = copy.deepcopy(info)
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(
                new_project=str(Path(directory) / "keys.noxen"), project=None, skip_device_scan=True,
            ))
            async with app.run_test(size=(110, 60)) as pilot:
                app.query_one("#main_tabs").active = "tab_intercept"
                app._current_intercepted_entry = {"id": 1, "intent": info}
                app._enter_edit_mode()
                app._add_edit_extra_row("new_key", "string", "value", True)
                for theme in ("noxen-dark", "noxen-light"):
                    app.theme = theme
                    for width in (72, 110, 200):
                        await pilot.resize_terminal(width, 60)
                        await pilot.pause()
                        labels = list(app.query(ExtraKeyLabel))
                        header = app.query_one(".ef_x_key_header")
                        for label in labels:
                            self.assertEqual(label.region.width, header.region.width)
                            self.assertTrue(18 <= label.region.width <= 40)
                            self.assertEqual(label.can_focus, label.truncated or label.region.height > 1)
                            row = label.parent.parent
                            for widget in row.children:
                                self.assertEqual(widget.region.y, row.region.y)
                            self.assertEqual(row.region.height, label.parent.region.height)
                        self.assertGreater(labels[1].region.height, 1)
                        for previous, following in zip(app.query(".ef_x_row"), list(app.query(".ef_x_row"))[1:]):
                            self.assertEqual(following.region.y - previous.region.bottom, 1)
                        new_key = app.query_one(".ef_x_key_input", Input)
                        self.assertEqual(new_key.region.width, header.region.width)
                        self.assertGreater(app.query_one(".ef_x_value_header").region.width, 4)
                        self.assertLess(len(str(labels[2].render())), 140)
                        self.assertEqual(str(labels[2].render()), keys[2][:96] + "…")
                        self.assertFalse(labels[0].can_focus)
                        self.assertTrue(labels[1].can_focus)
                        self.assertTrue(labels[2].can_focus)
                        ellipsis_style = labels[2].get_component_rich_style("extra-key--ellipsis")
                        self.assertNotEqual(ellipsis_style.color, labels[2].rich_style.color)
                        self.assertEqual(labels[2].content.spans[-1].style, ellipsis_style)
                        self.assertEqual(len(app.query(".ef_x_key_view")), 1)
                        self.assertEqual(str(labels[3].render()), keys[3])
                        self.assertIn(r"\n", str(labels[-1].render()))

                label = list(app.query(ExtraKeyLabel))[2]
                label.focus()
                await pilot.press("enter")
                await pilot.pause()
                self.assertIsInstance(app.screen, ExtraKeyModal)
                area = app.screen.query_one(TextArea)
                self.assertTrue(area.read_only)
                self.assertEqual(area.text, keys[2])
                await pilot.press("z", "backspace")
                self.assertEqual(area.text, keys[2])
                await pilot.press("escape")
                await pilot.pause()
                self.assertNotIsInstance(app.screen, ExtraKeyModal)
                self.assertTrue(app._edit_mode)
                self.assertEqual(info, original)
                self.assertEqual(list(app._collect_edit_draft()["extras"]), keys + ["new_key"])
                view_button = app.query_one(".ef_x_key_view")
                view_button.scroll_visible(animate=False)
                await pilot.pause()
                await pilot.click(view_button)
                await pilot.pause()
                self.assertEqual(app.screen.query_one(TextArea).text, keys[2])
                await pilot.press("escape")
                await pilot.pause()
                # A short key is plain text; a wrapped key still opens on click.
                label = list(app.query(ExtraKeyLabel))[0]
                label.scroll_visible(animate=False)
                await pilot.pause()
                await pilot.click(label)
                await pilot.pause()
                self.assertNotIsInstance(app.screen, ExtraKeyModal)
                label = list(app.query(ExtraKeyLabel))[1]
                await pilot.click(label)
                await pilot.pause()
                self.assertEqual(app.screen.query_one(TextArea).text, keys[1])
                await pilot.click("#extra_key_close")
                await pilot.pause()
                self.assertEqual(len(app._edit_extra_rows), len(keys) + 1)
                app._exit_edit_mode()
                await pilot.pause()
