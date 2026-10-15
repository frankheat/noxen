import copy
import os
import tempfile
import unittest
from types import SimpleNamespace

from textual.widgets import ContentSwitcher, DataTable, Input, Label, RichLog, Switch
from textual.widgets.data_table import ColumnKey

from noxen.app import NoxenApp, markup_renderable


def project_args(path):
    return SimpleNamespace(project=None, new_project=path, skip_device_scan=True)


SNAPSHOT = {
    "identity": {"package": "com.x", "label": "X", "versionName": "1.0", "versionCode": "1",
                 "uid": 10148, "pid": 1, "processName": "com.x"},
    "build": {"targetSdk": 34, "minSdk": 24, "debuggable": True, "allowBackup": True,
              "cleartextPermitted": False, "testOnly": False, "nscPresent": False},
    "signing": {"sha256": ["AABB"], "multipleSigners": False},
    "permissions": [
        {"name": "com.x.P", "source": "requested", "granted": True, "level": "normal"},
        {"name": "com.x.P", "source": "defined", "granted": None, "level": "normal"},
    ],
    "components": [
        {"name": "com.x.R2", "type": "receiver", "exported": True,
         "permission": {"name": "com.x.P", "level": "normal"}, "enabled": True, "enabledRuntime": 0},
        {"name": "com.x.R1", "type": "receiver", "exported": True, "permission": None,
         "enabled": True, "enabledRuntime": 0},
        {"name": "com.x.A1", "type": "activity", "exported": False, "permission": None,
         "enabled": True, "enabledRuntime": 0},
    ],
}


class MarkupRenderableTests(unittest.TestCase):
    def test_emoji_shortcodes_are_not_substituted(self):
        # A signing SHA-256 byte 0xCD makes the value contain ":CD:", which Rich would
        # otherwise turn into the 💿 emoji shortcode. Data must render verbatim.
        rendered = markup_renderable("  0A:71:CF:CD:A0:45")
        self.assertNotIn("💿", rendered.plain)
        self.assertIn("CF:CD:A0", rendered.plain)

    def test_style_tags_still_apply(self):
        rendered = markup_renderable("[bold]\\[SIGNING][/bold]")
        # escaped brackets render literally, and the style tag is consumed (not shown)
        self.assertEqual(rendered.plain, "[SIGNING]")


class InfoTabTests(unittest.IsolatedAsyncioTestCase):
    async def test_refresh_keeps_disabled_components_visible_under_search_and_exposed_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = NoxenApp(project_args(os.path.join(tmp, "disabled.noxen")))
            async with app.run_test(size=(120, 40)) as pilot:
                snapshot = copy.deepcopy(SNAPSHOT)
                receiver = snapshot["components"][1]
                receiver["enabledRuntime"] = 2
                app._apply_app_info(snapshot)
                app.query_one("TabbedContent").active = "tab_info"
                app._switch_info_view("info_nav_components")
                app.query_one("#info_comp_exposed", Switch).value = True
                app.query_one("#info_comp_search", Input).value = "R1"
                app._info_sort["info_comp_table"] = ("enabled", False)
                await pilot.pause()
                table = app.query_one("#info_comp_table", DataTable)
                self.assertEqual(table.row_count, 1)
                self.assertEqual(table.get_row("com.x.R1")[3:5], ["open", "no"])
                for runtime, expected in ((1, "yes"), (0, "yes"), (2, "no")):
                    receiver["enabledRuntime"] = runtime
                    app._apply_app_info(copy.deepcopy(snapshot))
                    await pilot.pause()
                    self.assertEqual(table.row_count, 1)
                    self.assertEqual(table.get_row("com.x.R1")[3:5], ["open", expected])
                    self.assertEqual(len(app._app_info["components"]), 3)
                    self.assertEqual(app._info_sort["info_comp_table"], ("enabled", False))

    async def test_component_detail_resize_only_in_components_view(self):
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                app = NoxenApp(project_args(os.path.join(tmp, "p.noxen")))
                async with app.run_test(size=(120, 40)) as pilot:
                    app.query_one("TabbedContent").active = "tab_info"
                    app._switch_info_view("info_nav_components")
                    await pilot.pause()
                    self.assertFalse(app.check_action("resize_panel_up", ()))

                    app._apply_app_info(SNAPSHOT)
                    await pilot.pause()
                    detail = app.query_one("#info_comp_detail", RichLog)
                    table = app.query_one("#info_comp_table", DataTable)
                    initial_detail = detail.size.height
                    initial_table = table.size.height
                    self.assertTrue(app.check_action("resize_panel_up", ()))

                    await pilot.press("alt+up")
                    await pilot.pause()
                    self.assertEqual(detail.size.height, initial_detail + 1)
                    self.assertEqual(table.size.height, initial_table - 1)

                    await pilot.press("alt+down")
                    await pilot.pause()
                    self.assertEqual(detail.size.height, initial_detail)
                    self.assertEqual(table.size.height, initial_table)

                    app._switch_info_view("info_nav_permissions")
                    await pilot.pause()
                    self.assertFalse(app.check_action("resize_panel_up", ()))
                    await pilot.press("alt+up")
                    await pilot.pause()
                    app._switch_info_view("info_nav_components")
                    await pilot.pause()
                    self.assertEqual(detail.size.height, initial_detail)

                    app._switch_info_view("info_nav_overview")
                    await pilot.pause()
                    self.assertFalse(app.check_action("resize_panel_down", ()))
                    app._clear_info_tab()
                    app._switch_info_view("info_nav_components")
                    await pilot.pause()
                    self.assertFalse(app.check_action("resize_panel_up", ()))
            finally:
                os.chdir(cwd)

    async def test_apply_app_info_populates_and_filters(self):
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                app = NoxenApp(project_args(os.path.join(tmp, "p.noxen")))
                async with app.run_test(size=(120, 40)) as pilot:
                    # empty until a snapshot arrives
                    self.assertFalse(app.query_one("#info_switcher", ContentSwitcher).display)

                    app._apply_app_info(SNAPSHOT)
                    await pilot.pause()

                    self.assertTrue(app.query_one("#info_switcher", ContentSwitcher).display)
                    self.assertFalse(app.query_one("#info_empty", Label).display)
                    self.assertEqual(app.query_one("#info_comp_table", DataTable).row_count, 3)
                    self.assertEqual(app.query_one("#info_perm_table", DataTable).row_count, 2)

                    # "Exposed only" → R2 (normal), R1 (none); A1 not exported
                    app.query_one("#info_comp_exposed", Switch).value = True
                    await pilot.pause()
                    self.assertEqual(app.query_one("#info_comp_table", DataTable).row_count, 2)

                    # nav switches the content
                    app._switch_info_view("info_nav_components")
                    await pilot.pause()
                    self.assertEqual(app.query_one("#info_switcher", ContentSwitcher).current, "info_view_components")

                    # disconnect clears back to empty
                    app._clear_info_tab()
                    await pilot.pause()
                    self.assertFalse(app.query_one("#info_switcher", ContentSwitcher).display)
                    self.assertIsNone(app._app_info)
            finally:
                os.chdir(cwd)


    async def test_sorting_by_header_keeps_selection(self):
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                app = NoxenApp(project_args(os.path.join(tmp, "p.noxen")))
                async with app.run_test(size=(120, 40)) as pilot:
                    app._apply_app_info(SNAPSHOT)
                    app.query_one("TabbedContent").active = "tab_info"
                    app._switch_info_view("info_nav_components")
                    await pilot.pause()
                    table = app.query_one("#info_comp_table", DataTable)

                    def row_names():
                        return [key.value for key in table.rows]

                    def header(key):
                        return str(table.columns[ColumnKey(key)].label)

                    async def click_header(key):
                        column = table.columns[ColumnKey(key)]
                        index = list(table.columns).index(ColumnKey(key))
                        table.post_message(DataTable.HeaderSelected(table, ColumnKey(key), index, column.label))
                        await pilot.pause()
                        await pilot.pause()

                    # initial state: by component type (activity first), ties by name
                    self.assertEqual(row_names(), ["com.x.A1", "com.x.R1", "com.x.R2"])
                    self.assertEqual(header("type"), "Type ↑")

                    # select R2, then sort by Access: open ones first, not exported last
                    table.move_cursor(row=2)
                    await pilot.pause()
                    await click_header("access")
                    self.assertEqual(row_names(), ["com.x.R1", "com.x.R2", "com.x.A1"])
                    self.assertEqual(header("access"), "Access ↑")
                    self.assertEqual(header("type"), "Type")
                    self.assertEqual(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value, "com.x.R2")
                    self.assertTrue(app.query_one("#info_comp_detail", RichLog).lines)

                    # second click reverses: not exported first, ties still by name
                    await click_header("access")
                    self.assertEqual(row_names(), ["com.x.A1", "com.x.R1", "com.x.R2"])
                    self.assertEqual(header("access"), "Access ↓")
                    self.assertEqual(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value, "com.x.R2")
            finally:
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
