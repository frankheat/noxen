import os
import tempfile
import unittest
from types import SimpleNamespace

from textual.widgets import ContentSwitcher, DataTable, Label, RichLog, Switch
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
