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
    HomeLogo,
    INTERCEPT_COMMAND_OUTPUT_HEIGHT,
    MAX_COMMAND_OUTPUT_HEIGHT,
    MIN_PANEL_HEIGHT,
    NoxenApp,
    clamp_height,
    max_primary_panel_height,
)
from noxen.logging_ui import log_debug, log_info


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
