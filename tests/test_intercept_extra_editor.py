import asyncio
import os
import tempfile
import unittest
from types import SimpleNamespace

from textual.widgets import Button, Input, Select

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

    async def test_edit_mode_bindings_labels_and_cancel(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                app = NoxenApp(project_args(os.path.join(tmp, "bindings.noxen")))
                async with app.run_test(size=(120, 36)) as pilot:
                    app.query_one("#main_tabs").active = "tab_intercept"
                    app._current_intercepted_entry = {
                        "intent": {"categories": [], "extras": {}, "flags": 0}
                    }
                    app.set_intercept_state(True)
                    app._enter_edit_mode()
                    await pilot.pause()

                    self.assertTrue(app.check_action("apply_edit", ()))
                    self.assertTrue(app.check_action("cancel_edit", ()))
                    self.assertTrue(app.check_action("drop_current", ()))
                    self.assertFalse(app.check_action("forward_current", ()))
                    self.assertEqual(
                        app.screen.active_bindings["ctrl+f"].binding.description,
                        "Apply & Forward",
                    )
                    self.assertEqual(str(app.query_one("#btn_forward", Button).label), "Apply & Forward")
                    self.assertIn("apply-forward", app.query_one("#btn_forward", Button).classes)
                    self.assertGreaterEqual(app.query_one("#btn_forward", Button).region.width, 21)
                    self.assertFalse(app.query_one("#btn_edit", Button).display)
                    self.assertTrue(app.query_one("#btn_cancel_edit", Button).display)

                    app.query_one("#ef_action", Input).focus()
                    await pilot.press("escape")
                    await pilot.pause()
                    self.assertFalse(app._edit_mode)
                    self.assertEqual(str(app.query_one("#btn_forward", Button).label), "Forward")
                    self.assertNotIn("apply-forward", app.query_one("#btn_forward", Button).classes)
                    self.assertTrue(app.query_one("#btn_edit", Button).display)
                    self.assertFalse(app.query_one("#btn_cancel_edit", Button).display)
                    self.assertFalse(app.check_action("apply_edit", ()))
            finally:
                os.chdir(previous_cwd)

    async def test_ctrl_f_applies_and_forwards_from_edit_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                app = NoxenApp(project_args(os.path.join(tmp, "forward.noxen")))
                async with app.run_test(size=(120, 36)) as pilot:
                    app.query_one("#main_tabs").active = "tab_intercept"
                    app._current_intercepted_entry = {
                        "intent": {"action": "old", "categories": [], "extras": {}, "flags": 0}
                    }
                    app.set_intercept_state(True)
                    forwarded = []
                    app._apply_mods_and_forward_worker = lambda mods: forwarded.append(mods)
                    app._enter_edit_mode()
                    app.query_one("#ef_action", Input).value = "new"
                    app.query_one("#ef_action", Input).focus()

                    await pilot.press("ctrl+f")
                    await pilot.pause()

                    self.assertEqual(forwarded, [[("action", "", "new", "")]])
                    self.assertTrue(app._edit_mode)
                    self.assertTrue(app._edit_forward_pending)
                    self.assertEqual(str(app.query_one("#btn_forward", Button).label), "Applying…")
                    self.assertTrue(app.query_one("#edit_form").disabled)
                    self.assertFalse(app.check_action("apply_edit", ()))
                    self.assertFalse(app.check_action("drop_current", ()))

                    app.set_intercept_state(False)
                    await pilot.pause()
                    self.assertFalse(app._edit_mode)
            finally:
                os.chdir(previous_cwd)

    async def test_ctrl_f_forwards_and_ctrl_d_drops_outside_edit_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                app = NoxenApp(project_args(os.path.join(tmp, "intercept-bindings.noxen")))
                async with app.run_test(size=(120, 36)) as pilot:
                    app.query_one("#main_tabs").active = "tab_intercept"
                    app._current_intercepted_entry = {
                        "intent": {"categories": [], "extras": {}, "flags": 0}
                    }
                    commands = []
                    app.process_command_worker = lambda command: commands.append(command)
                    app.set_intercept_state(True)
                    await pilot.pause()

                    self.assertTrue(app.check_action("forward_current", ()))
                    self.assertTrue(app.check_action("drop_current", ()))
                    self.assertFalse(app.check_action("apply_edit", ()))
                    self.assertFalse(app.check_action("cancel_edit", ()))
                    self.assertEqual(
                        app.screen.active_bindings["ctrl+f"].binding.description,
                        "Forward",
                    )
                    self.assertEqual(
                        app.screen.active_bindings["ctrl+d"].binding.description,
                        "Drop",
                    )

                    await pilot.press("ctrl+f")
                    await pilot.press("ctrl+d")
                    await pilot.pause()

                    self.assertEqual(commands, ["forward", "drop"])
            finally:
                os.chdir(previous_cwd)

    async def test_frida_failure_restores_the_populated_editor(self):
        class RejectingSession:
            connection_failed_cb = None
            disconnected_cb = None

            @staticmethod
            def is_ready():
                return True

            @staticmethod
            def stage_mod(*_args):
                return False

            @staticmethod
            def cleanup():
                return None

        with tempfile.TemporaryDirectory() as tmp:
            previous_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                app = NoxenApp(project_args(os.path.join(tmp, "frida-failure.noxen")))
                async with app.run_test(size=(120, 36)) as pilot:
                    app.query_one("#main_tabs").active = "tab_intercept"
                    app._current_intercepted_entry = {
                        "intent": {"action": "old", "categories": [], "extras": {}, "flags": 0}
                    }
                    app._current_decision_id = "decision"
                    app.frida_session = RejectingSession()
                    app.set_intercept_state(True)
                    app._enter_edit_mode()
                    app.query_one("#ef_action", Input).value = "new"

                    app._forward_from_edit_mode()
                    for _ in range(20):
                        await pilot.pause()
                        if not app._edit_forward_pending:
                            break
                    await app.workers.wait_for_complete()

                    self.assertFalse(app._edit_forward_pending)
                    self.assertTrue(app._edit_mode)
                    self.assertEqual(app.query_one("#ef_action", Input).value, "new")
                    self.assertFalse(app.query_one("#edit_form").disabled)
                    self.assertEqual(
                        str(app.query_one("#btn_forward", Button).label),
                        "Apply & Forward",
                    )
            finally:
                os.chdir(previous_cwd)

    async def test_invalid_flags_and_duplicate_extra_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                app = NoxenApp(project_args(os.path.join(tmp, "validation.noxen")))
                async with app.run_test(size=(120, 36)) as pilot:
                    app.query_one("#main_tabs").active = "tab_intercept"
                    app._current_intercepted_entry = {
                        "intent": {
                            "categories": [], "flags": 0,
                            "extras": {"token": {"type": "java.lang.String", "value": "old"}},
                        }
                    }
                    app._enter_edit_mode()
                    await pilot.pause()

                    app.query_one("#ef_flags", Input).value = "not-a-flag"
                    with self.assertRaisesRegex(ValueError, "Flags must be a 32-bit integer"):
                        app._collect_edit_mods()
                    app._forward_from_edit_mode()
                    await pilot.pause()
                    self.assertTrue(app.query_one("#ef_flags", Input).has_focus)
                    self.assertTrue(app._edit_mode)

                    app.query_one("#ef_flags", Input).value = ""
                    app._add_edit_extra_row("", None, "", is_new=True)
                    await pilot.pause()
                    row_number = max(app._edit_extra_rows)
                    app.query_one(f"#ef_xv_{row_number}", Input).value = "orphan value"
                    with self.assertRaisesRegex(ValueError, "Extra key is required"):
                        app._collect_edit_mods()
                    app._forward_from_edit_mode()
                    await pilot.pause()
                    self.assertTrue(app.query_one(f"#ef_xk_{row_number}", Input).has_focus)

                    app.query_one(f"#ef_xv_{row_number}", Input).value = ""
                    app.query_one(f"#ef_xk_{row_number}", Input).value = "token"
                    with self.assertRaisesRegex(ValueError, "Duplicate extra key: token"):
                        app._collect_edit_mods()

                    app.query_one(f"#ef_xk_{row_number}", Input).value = "fresh"
                    app._add_edit_extra_row("", None, "", is_new=True)
                    await pilot.pause()
                    second_row = max(app._edit_extra_rows)
                    app.query_one(f"#ef_xk_{second_row}", Input).value = "fresh"
                    with self.assertRaisesRegex(ValueError, "Duplicate extra key: fresh"):
                        app._collect_edit_mods()
            finally:
                os.chdir(previous_cwd)


if __name__ == "__main__":
    unittest.main()
