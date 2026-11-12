import os
import tempfile
import unittest
from types import SimpleNamespace

from textual.widgets import TabbedContent

from tests.ui_test_case import IsolatedAppTestCase

from noxen.app import NoxenApp, markup_renderable
from noxen.ui_theme import (
    DARK_COLORS,
    LIGHT_COLORS,
    NOXEN_DARK_THEME,
    NOXEN_LIGHT_THEME,
    themed_markup,
)


def _relative_luminance(color: str) -> float:
    channels = [int(color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [
        channel / 12.92 if channel <= 0.04045
        else ((channel + 0.055) / 1.055) ** 2.4
        for channel in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(first: str, second: str) -> float:
    bright, dark = sorted(
        (_relative_luminance(first), _relative_luminance(second)),
        reverse=True,
    )
    return (bright + 0.05) / (dark + 0.05)


class ThemePaletteTests(unittest.TestCase):
    def test_semantic_colors_meet_normal_text_contrast(self):
        palettes = (
            (NOXEN_DARK_THEME.panel, NOXEN_DARK_THEME.foreground, DARK_COLORS),
            (NOXEN_LIGHT_THEME.panel, NOXEN_LIGHT_THEME.foreground, LIGHT_COLORS),
        )
        for background, foreground, colors in palettes:
            with self.subTest(background=background):
                for color in (
                    foreground,
                    colors.success,
                    colors.warning,
                    colors.error,
                    colors.info,
                    colors.muted,
                ):
                    self.assertGreaterEqual(_contrast(color, background), 4.5)

    def test_semantic_markup_tracks_active_palette(self):
        source = "[#26a368]OK[/#26a368] [bold yellow]WARN[/bold yellow] [red]ERROR[/red]"
        light = themed_markup(source, dark=False)
        self.assertIn(LIGHT_COLORS.success, light)
        self.assertIn(LIGHT_COLORS.warning, light)
        self.assertIn(LIGHT_COLORS.error, light)
        self.assertNotIn("#26a368", light.lower())

    def test_markup_rendering_preserves_literal_data(self):
        rendered = markup_renderable("[yellow]A:CD:B[/yellow]", dark=False)
        self.assertEqual(rendered.plain, "A:CD:B")
        self.assertNotIn("💿", rendered.plain)


class ThemeRuntimeTests(IsolatedAppTestCase):
    async def test_theme_action_uses_paired_noxen_palettes(self):
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

                def assert_uniform_background():
                    background = app.screen.styles.background
                    for selector in (
                        "#home_form", "#intercept_header", "#intercept_output", "#edit_form",
                        "#history_search", "#history_table", "#history_detail", "#tab_history",
                        "#monitor_search", "#monitor_events", "#monitor_profiles",
                        "#monitor_hooks", "#monitor_detail", "#log_verbose_group", "#log_output",
                        "#history_input_bar", "#intercept_input_bar", "#info_perm_search",
                        "#info_perm_table", "#info_comp_table", "#info_comp_detail", "#tab_info",
                        "Footer",
                    ):
                        with self.subTest(theme=app.theme, selector=selector):
                            self.assertEqual(app.query_one(selector).background_colors[1], background)

                async with app.run_test(size=(120, 40)) as pilot:
                    self.assertEqual(app.theme, "noxen-dark")
                    self.assertEqual(app.current_theme.background, NOXEN_DARK_THEME.background)
                    self.assertEqual(app.query_one("#session_bar").styles.background, app.screen.styles.background)
                    self.assertEqual(app.query_one("#session_info").styles.color.hex, "#E8EFEC99")
                    assert_uniform_background()

                    app.action_toggle_theme()
                    await pilot.pause()
                    await pilot.pause()

                    self.assertEqual(app.theme, "noxen-light")
                    self.assertEqual(app.current_theme.background, NOXEN_LIGHT_THEME.background)
                    self.assertFalse(app.current_theme.dark)
                    self.assertEqual(app.screen.styles.background.hex, "#FFFFFF")
                    self.assertEqual(app.screen.styles.color.hex, "#17211D")
                    self.assertEqual(app.query_one("#session_bar").styles.background, app.screen.styles.background)
                    self.assertEqual(app.query_one("#session_info").styles.color.hex, LIGHT_COLORS.muted)
                    self.assertEqual(
                        app.query_one("#log_verbose_label").styles.color.hex,
                        "#17211D",
                    )
                    assert_uniform_background()
                    self.assertEqual(
                        app.query_one("#settings_save").styles.color.hex,
                        "#17211D",
                    )

                    intercept = app.query_one("#intercept_toggle")
                    intercept.remove_class("intercept-on")
                    intercept.add_class("intercept-off")
                    await pilot.pause()
                    self.assertGreaterEqual(
                        _contrast(intercept.styles.color.hex, NOXEN_LIGHT_THEME.panel),
                        6.5,
                    )

                    app._apply_app_info({
                        "identity": {"package": "dev.test"},
                        "build": {},
                        "signing": {},
                        "permissions": [],
                        "components": [],
                    })
                    app.query_one("#main_tabs").active = "tab_info"
                    app.query_one("#info_views", TabbedContent).active = "info_view_permissions"
                    await pilot.pause()
                    permission_search = app.query_one("#info_perm_search")
                    permission_search.focus()
                    await pilot.pause()
                    self.assertEqual(
                        permission_search.styles.border.top[1],
                        app.query_one("#history_search").styles.border.top[1],
                    )
                    table = app.query_one("#info_perm_table")
                    table.focus()
                    await pilot.pause()
                    self.assertTrue(table.has_focus)
                    self.assertEqual(table.styles.background_tint.a, 0)
                    self.assertEqual(
                        table.get_component_styles("datatable--header").background_tint.a,
                        0,
                    )
            finally:
                os.chdir(cwd)

    async def test_action_buttons_have_visible_semantic_hover(self):
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
                    app.query_one("#main_tabs").active = "tab_settings"
                    await pilot.pause()
                    settings_save = app.query_one("#settings_save")
                    self.assertEqual(settings_save.styles.color.hex, "#E8EFEC")
                    await pilot.hover("#settings_save")
                    await pilot.pause()
                    self.assertEqual(settings_save.styles.color.hex, DARK_COLORS.success)

                    app.query_one("#main_tabs").active = "tab_history"
                    await pilot.pause()
                    await pilot.click("#btn_history_stack")
                    await pilot.pause()
                    stack_save = app.screen.query_one("#sm_save")
                    self.assertEqual(stack_save.styles.color.hex, "#E8EFEC")
                    await pilot.hover("#sm_save")
                    await pilot.pause()
                    self.assertEqual(stack_save.styles.color.hex, DARK_COLORS.success)
                    await pilot.click("#sm_close")
                    await pilot.pause()

                    await pilot.click("#btn_history_filters")
                    await pilot.pause()
                    add_filter = app.screen.query_one("#hfm_btn_add_filter")
                    self.assertEqual(add_filter.styles.color.hex, "#E8EFEC")
                    await pilot.hover("#hfm_btn_add_filter")
                    await pilot.pause()
                    self.assertEqual(add_filter.styles.color.hex, DARK_COLORS.success)
            finally:
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
