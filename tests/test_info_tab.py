import os
import tempfile
import unittest
from types import SimpleNamespace

from textual.widgets import ContentSwitcher, DataTable, Label, Switch

from noxen.app import NoxenApp


def project_args(path):
    return SimpleNamespace(project=None, new_project=path)


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


if __name__ == "__main__":
    unittest.main()
