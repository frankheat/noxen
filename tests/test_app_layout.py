import asyncio
import os
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from textual.containers import Horizontal
from textual.widgets import Label, Switch

from tests.ui_test_case import IsolatedAppTestCase

from noxen.app import (
    HISTORY_COMMAND_OUTPUT_HEIGHT,
    HomeLayout,
    HomeLogo,
    INTERCEPT_COMMAND_OUTPUT_HEIGHT,
    MAX_COMMAND_OUTPUT_HEIGHT,
    MIN_PANEL_HEIGHT,
    NoxenApp,
    clamp_height,
    max_primary_panel_height,
)
from noxen.logging_ui import log_debug, log_info
from noxen.sender_ui import SenderPane


def css_int_property(selector: str, property_name: str) -> int:
    css_path = Path(__file__).resolve().parents[1] / "src" / "noxen" / "noxen.tcss"
    css = css_path.read_text(encoding="utf-8")
    match = re.search(rf"{re.escape(selector)}\s*\{{[^}}]*{property_name}:\s*(\d+);", css, re.S)
    if match is None:
        raise AssertionError(f"{selector} {property_name} not found in noxen.tcss")
    return int(match.group(1))


def css_property(selector: str, property_name: str) -> str:
    css_path = Path(__file__).resolve().parents[1] / "src" / "noxen" / "noxen.tcss"
    css = css_path.read_text(encoding="utf-8")
    match = re.search(rf"{re.escape(selector)}\s*\{{[^}}]*{property_name}:\s*([^;]+);", css, re.S)
    if match is None:
        raise AssertionError(f"{selector} {property_name} not found in noxen.tcss")
    return match.group(1).strip()


def css_height(selector: str) -> int:
    return css_int_property(selector, "height")


class AppLayoutTests(unittest.TestCase):
    def test_command_output_defaults_match_tcss(self):
        self.assertEqual(css_height("#intercept_cmd_output"), INTERCEPT_COMMAND_OUTPUT_HEIGHT)
        self.assertEqual(css_height("#history_cmd_output"), HISTORY_COMMAND_OUTPUT_HEIGHT)

    def test_command_output_defaults_are_inside_resize_bounds(self):
        self.assertGreaterEqual(INTERCEPT_COMMAND_OUTPUT_HEIGHT, MIN_PANEL_HEIGHT)
        self.assertLessEqual(INTERCEPT_COMMAND_OUTPUT_HEIGHT, MAX_COMMAND_OUTPUT_HEIGHT)
        self.assertGreaterEqual(HISTORY_COMMAND_OUTPUT_HEIGHT, MIN_PANEL_HEIGHT)
        self.assertLessEqual(HISTORY_COMMAND_OUTPUT_HEIGHT, MAX_COMMAND_OUTPUT_HEIGHT)


    def test_home_anr_bypass_label_width_fits_text(self):
        label = "Input ANR bypass (experimental)"
        width = css_property("#home_anr_bypass_label", "width")
        if width != "auto":
            self.assertGreaterEqual(int(width), len(label))

    def test_home_logo_keeps_its_half_blocks_at_every_scale(self):
        self.assertEqual([cells[0] for cells in HomeLogo.brand_lines(1)], HomeLogo._ART)
        # The top-right notch of "n" fills only the lower half of its cell.
        n_top = [line[:10] for line in HomeLogo.brand_lines(2)[0]]
        self.assertEqual(n_top, ["████████  ", "██████████"])
        n_top = [line[:15] for line in HomeLogo.brand_lines(3)[0]]
        self.assertEqual(n_top, ["████████████   ", "████████████▄▄▄", "███████████████"])

    def test_home_logo_fit_considers_both_terminal_dimensions(self):
        self.assertEqual(HomeLogo.fit(29, 16, stacked=True)[0], 1)
        self.assertEqual(HomeLogo.fit(28, 16, stacked=True), (0, 0))
        self.assertEqual(HomeLogo.fit(87, 18, stacked=False)[0], 3)
        self.assertEqual(HomeLogo.fit(87, 15, stacked=False)[0], 2)
        self.assertEqual(HomeLogo.fit(87, 12, stacked=False), (1, 0))

    def test_clamp_height_applies_minimum_and_optional_maximum(self):
        self.assertEqual(clamp_height(1, minimum=3), 3)
        self.assertEqual(clamp_height(5, minimum=3), 5)
        self.assertEqual(clamp_height(30, minimum=3, maximum=20), 20)

    def test_max_primary_panel_height_preserves_secondary_minimum(self):
        self.assertEqual(max_primary_panel_height(10, 8, secondary_minimum=3), 15)
        self.assertEqual(max_primary_panel_height(1, 1, secondary_minimum=3), MIN_PANEL_HEIGHT)

    def test_log_verbose_keeps_hidden_debug_entries_available(self):
        fake = _FakeLogApp()

        NoxenApp.write_log(fake, log_debug("Hidden detail", "agent"))
        NoxenApp.write_log(fake, log_info("Visible event", "frida"))

        self.assertEqual(len(fake._log_entries), 2)
        self.assertEqual(fake.written, [log_info("Visible event", "frida")])

        fake._log_verbose = True
        NoxenApp._refresh_log_output(fake)

        self.assertEqual(fake.output.lines, [
            log_debug("Hidden detail", "agent"),
            log_info("Visible event", "frida"),
        ])


class HomeZoomTests(IsolatedAppTestCase):
    async def test_resize_keeps_original_logo_and_form_accessible(self):
        app = NoxenApp(SimpleNamespace(project=None, new_project=str(self.settings_path.parent / "home-zoom"),
                                       skip_device_scan=True))
        async with app.run_test(size=(185, 36)) as pilot:
            layout = app.query_one(HomeLayout)
            logo = app.query_one(HomeLogo)
            form = app.query_one("#home_form")
            self.assertIn(HomeLogo.brand_lines(2)[0][0], str(logo.content))
            for width, height, stacked, scale in (
                (82, 32, False, 1), (64, 31, True, 2), (29, 26, True, 1),
                (28, 26, True, 0), (140, 12, True, 1), (185, 36, False, 2),
            ):
                with self.subTest(width=width, height=height):
                    await pilot.resize_terminal(width, height)
                    await pilot.pause()
                    self.assertEqual(layout.has_class("home-stacked"), stacked)
                    if scale:
                        self.assertGreaterEqual(logo.content_size.width, scale * HomeLogo.WIDTH)
                        self.assertIn(HomeLogo.brand_lines(scale)[0][0], str(logo.content))
                    else:
                        self.assertIn("noxen", str(logo.content))
                        self.assertNotIn("█", str(logo.content))
                    if stacked:
                        self.assertGreaterEqual(form.region.y, logo.region.bottom)
                        self.assertGreater(layout.max_scroll_y, 0)
                        if width == 29:
                            layout.scroll_end(animate=False, immediate=True)
                            await pilot.pause()
                            button = app.query_one("#home_btn")
                            self.assertGreaterEqual(button.region.y, layout.region.y)
                            self.assertLessEqual(button.region.bottom, layout.region.bottom)
                            layout.scroll_home(animate=False, immediate=True)
                            await pilot.pause()
                    else:
                        self.assertGreaterEqual(form.region.x, logo.region.right)
                        self.assertEqual(form.region.y, logo.region.y)
                        self.assertEqual(layout.max_scroll_y, 0)


class ShortcutOrderTests(IsolatedAppTestCase):
    async def test_app_keys_keep_their_order_across_tabs_and_editor_focus(self):
        app = NoxenApp(SimpleNamespace(project=None, new_project=str(self.settings_path.parent / "shortcuts"),
                                       skip_device_scan=True))
        async with app.run_test(size=(120, 38)) as pilot:
            tabs = app.query_one("#main_tabs")

            async def open_tab(tab_id):
                # Drain any Focused message from the previous pane before clicking
                # the next tab. A queued focus change can reactivate its own pane.
                await pilot.pause()
                self.assertTrue(await pilot.click(tabs.get_tab(tab_id)))
                await pilot.pause()
                self.assertEqual(tabs.active, tab_id)
                self.assertEqual(app._active_tab, tab_id)

            async def expect(*keys):
                for _ in range(50):
                    actual = tuple(key.key for key in app.query("FooterKey"))
                    if actual == keys:
                        return
                    await asyncio.sleep(0.05)
                self.assertEqual(actual, keys)

            await expect("ctrl+q")
            await open_tab("tab_sender")
            sender = app.query_one(SenderPane)
            sender.editor.area.focus()
            await expect("ctrl+q", "alt+left", "alt+right", "ctrl+space", "ctrl+o", "ctrl+n")
            sender.query_one("#sender_new").focus()
            await expect("ctrl+q", "alt+left", "alt+right")
            await open_tab("tab_history")
            await expect("ctrl+q", "ctrl+l", "alt+up", "alt+down", "ctrl+b", "ctrl+r", "ctrl+t")
            await open_tab("tab_log")
            await expect("ctrl+q", "ctrl+l")
            await open_tab("tab_info")
            await expect("ctrl+q", "ctrl+g")
            await open_tab("tab_settings")
            await expect("ctrl+q")
            await open_tab("tab_intercept")
            app._current_intercepted_entry = {"id": 1, "method": "getIntent", "intent": {"flags": 0}}
            app._intent_blocked = True
            app._enter_edit_mode()
            await expect("ctrl+q", "alt+up", "alt+down", "ctrl+b", "ctrl+f", "ctrl+d", "escape",
                         "ctrl+space", "ctrl+o", "ctrl+n")


class SwitchControlLayoutTests(IsolatedAppTestCase):
    async def test_log_verbose_matches_info_exposed_control_structure(self):
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                args = SimpleNamespace(
                    project=None,
                    new_project=os.path.join(tmp, "p.noxen"),
                    skip_device_scan=True,
                )
                app = NoxenApp(args)
                async with app.run_test(size=(120, 40)) as pilot:
                    await pilot.pause()
                    log_group = app.query_one("#log_verbose_group", Horizontal)
                    info_group = app.query_one("#info_exposed_group", Horizontal)

                    self.assertTrue(log_group.has_class("switch-control"))
                    self.assertTrue(info_group.has_class("switch-control"))
                    self.assertEqual(
                        [child.id for child in log_group.children],
                        ["log_verbose", "log_verbose_label"],
                    )
                    self.assertIsInstance(log_group.children[0], Switch)
                    self.assertIsInstance(log_group.children[1], Label)
                    self.assertTrue(log_group.children[1].has_class("switch-control-label"))
            finally:
                os.chdir(cwd)


class _FakeLogOutput:
    def __init__(self):
        self.lines = []

    def clear(self):
        self.lines.clear()

    def write(self, text):
        self.lines.append(text)


class _FakeLogApp:
    def __init__(self):
        self._log_verbose = False
        self._log_entries = []
        self.written = []
        self.output = _FakeLogOutput()

    def _write_rich(self, _widget_id, text, _notify=False):
        self.written.append(text)

    def _is_log_visible(self, text):
        return NoxenApp._is_log_visible(self, text)

    def query_one(self, _selector, _widget_type):
        return self.output


class ButtonSpacingTests(IsolatedAppTestCase):
    async def test_every_button_has_the_same_space_on_each_side_of_its_label(self):
        from rich.cells import cell_len
        from textual.widgets import Button, TabbedContent

        with tempfile.TemporaryDirectory() as tmp:
            app = NoxenApp(SimpleNamespace(project=None, new_project=os.path.join(tmp, "p.noxen"),
                                           skip_device_scan=True))
            async with app.run_test(size=(140, 45)) as pilot:
                def check(where):
                    visible = set(app.screen._compositor.visible_widgets)
                    buttons = [b for b in app.screen.query(Button) if b in visible and b.region.width]
                    self.assertTrue(buttons, where)
                    for button in buttons:
                        spare = button.content_region.width - cell_len(str(button.label))
                        # Textual centres the label: an odd spare column would all go to the right.
                        self.assertEqual(spare % 2, 0, f"{where}: {button.id} {str(button.label)!r}")

                tabs = app.query_one("#main_tabs", TabbedContent)
                for pane in ("tab_home", "tab_intercept", "tab_history", "tab_monitor", "tab_sender",
                             "tab_mcp", "tab_log", "tab_settings"):
                    tabs.active = pane
                    await pilot.pause(0.3)
                    check(pane)
                # A button whose label changes stays even with each label.
                tabs.active = "tab_intercept"
                for enabled in (True, False):
                    app.update_intercept_button(enabled)
                    await pilot.pause()
                    check(f"intercept {enabled}")
                connect = app.query_one("#home_btn", Button)
                tabs.active = "tab_home"
                for label in ("Connect", "Connecting…"):
                    connect.label = label
                    await pilot.pause()
                    check(label)

                # In History, To Sender sits between the search bar and the columns button.
                tabs.active = "tab_history"
                await pilot.pause(0.3)
                search, sender, columns = (app.query_one(selector).region
                                           for selector in ("#history_search", "#btn_history_sender", "#btn_columns"))
                self.assertLess(search.right, sender.x)
                self.assertLess(sender.right, columns.x)


if __name__ == "__main__":
    unittest.main()
