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

    async def test_opaque_and_truncated_key_extras_are_safely_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                app = NoxenApp(project_args(os.path.join(tmp, "opaque.noxen")))
                async with app.run_test(size=(120, 36)) as pilot:
                    app.query_one("#main_tabs").active = "tab_intercept"
                    app._current_intercepted_entry = {
                        "intent": {
                            "categories": [], "flags": 0,
                            "extras": {"account": {
                                "type": "com.example.Account", "value": "(opaque object)",
                                "editable": False,
                            }, "long-key…": {
                                "type": "java.lang.String", "value": "value",
                                "editable": False, "keyTruncated": True,
                            }},
                        }
                    }

                    app._enter_edit_mode()
                    await pilot.pause()

                    rows_by_key = {row["key"]: number for number, row in app._edit_extra_rows.items()}
                    opaque_row = rows_by_key["account"]
                    truncated_row = rows_by_key["long-key…"]
                    self.assertTrue(app.query_one(f"#ef_xv_{opaque_row}", Input).disabled)
                    self.assertFalse(app.query_one(f"#ef_xrm_{opaque_row}").disabled)
                    self.assertTrue(app.query_one(f"#ef_xv_{truncated_row}", Input).disabled)
                    self.assertTrue(app.query_one(f"#ef_xrm_{truncated_row}").disabled)
            finally:
                os.chdir(previous_cwd)


if __name__ == "__main__":
    unittest.main()
