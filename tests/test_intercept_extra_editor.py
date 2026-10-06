import asyncio
import os
import tempfile
import unittest
from types import SimpleNamespace

from textual.widgets import Input, Select

from noxen.app import NoxenApp


def project_args(path: str) -> SimpleNamespace:
    return SimpleNamespace(project=None, new_project=path, skip_device_scan=True)


class InterceptExtraEditorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        asyncio.get_running_loop().slow_callback_duration = 1.0

    async def test_null_disables_value_and_invalid_collection_blocks_forward(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                app = NoxenApp(project_args(os.path.join(tmp, "extras.noxen")))
                async with app.run_test(size=(120, 36)) as pilot:
                    app.query_one("#main_tabs").active = "tab_intercept"
                    app._current_intercepted_entry = {
                        "intent": {"categories": [], "extras": {}, "flags": 0}
                    }
                    app._enter_edit_mode()
                    app._add_edit_extra_row("", None, "", is_new=True)
                    await pilot.pause()

                    row_number = max(app._edit_extra_rows)
                    type_select = app.query_one(f"#ef_xt_{row_number}", Select)
                    value_input = app.query_one(f"#ef_xv_{row_number}", Input)

                    type_select.value = "null"
                    await pilot.pause()
                    self.assertTrue(value_input.disabled)
                    self.assertEqual(value_input.placeholder, "not used")

                    type_select.value = "int[]"
                    await pilot.pause()
                    self.assertFalse(value_input.disabled)
                    self.assertEqual(value_input.placeholder, "1,2,3")
                    app.query_one(f"#ef_xk_{row_number}", Input).value = "ids"
                    value_input.value = "1,not-an-int"
                    with self.assertRaisesRegex(ValueError, "ids: Invalid int value"):
                        app._collect_edit_mods()
            finally:
                os.chdir(previous_cwd)


if __name__ == "__main__":
    unittest.main()
