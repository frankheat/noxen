import asyncio
import os
import tempfile
from types import SimpleNamespace

from textual.widgets import Input, Select

from noxen.app import NoxenApp
from noxen.modals import FilterModal
from tests.ui_test_case import IsolatedAppTestCase


def project_args_without_device_scan(path: str) -> SimpleNamespace:
    return SimpleNamespace(
        project=None,
        new_project=path,
        skip_device_scan=True,
    )


class PanelControlTests(IsolatedAppTestCase):
    async def asyncSetUp(self):
        asyncio.get_running_loop().slow_callback_duration = 1.0

    async def test_filter_modal_adds_edits_and_copies_a_provider_rule(self):
        app = NoxenApp(project_args_without_device_scan(str(self.settings_path.parent / "filters.noxen")))
        async with app.run_test(size=(100, 36)) as pilot:
            app.query_one("#main_tabs").active = "tab_intercept"
            await pilot.pause()
            self.assertFalse(app.query("#intercept_command_input"))
            self.assertFalse(app.query("#history_command_input"))
            await pilot.click("#btn_intercept_filters")
            await pilot.pause()
            modal = app.screen
            self.assertIsInstance(modal, FilterModal)
            modal.query_one("#hfm_pk_1", Select).value = "event"
            await pilot.pause()
            self.assertFalse(modal.query_one("#hfm_pv_1", Input).display)
            modal.query_one("#hfm_choice_1", Select).value = "provider"
            await pilot.click("#hfm_btn_add_pair")
            modal.query_one("#hfm_pk_2", Select).value = "authority"
            modal.query_one("#hfm_pv_2", Input).value = "dev.demo"
            await pilot.click("#hfm_btn_add_filter")
            expected = {"event": "provider", "authority": "dev.demo"}
            self.assertEqual(app.db.load_intercept_filters()[0]["rule"], expected)
            await pilot.click("#hfm_filters_table", offset=(10, 2))
            await pilot.click("#hfm_btn_copy")
            self.assertEqual(app.db.load_history_filters()[0]["rule"], expected)
            await pilot.click("#hfm_btn_edit")
            await pilot.pause()
            pid = modal._active_pairs[-1]
            modal.query_one(f"#hfm_pv_{pid}", Input).value = "dev.other"
            await pilot.click("#hfm_btn_add_filter")
            self.assertEqual(app.db.load_intercept_filters()[0]["rule"]["authority"], "dev.other")
            self.assertEqual(app.db.load_history_filters()[0]["rule"], expected)
            await pilot.resize_terminal(60, 30)
            await pilot.pause()
            copy_button = modal.query_one("#hfm_btn_copy")
            self.assertLessEqual(copy_button.region.right, copy_button.parent.content_region.right)
            condition = modal.query_one(f"#hfm_pk_{modal._active_pairs[0]}", Select)
            await pilot.click(condition)
            await pilot.pause()
            overlay = condition.query_one("SelectOverlay")
            lines = [overlay.render_line(y).text.strip() for y in range(overlay.scrollable_content_region.height)]
            for label in ("Authority", "Component", "Direction"):
                self.assertIn(label, lines)

    async def test_intercept_action_buttons_use_state_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                app = NoxenApp(project_args_without_device_scan(os.path.join(tmp, "missing.noxen")))
                async with app.run_test(size=(100, 32)):
                    intercept = app.query_one("#intercept_toggle")
                    forward = app.query_one("#btn_forward")
                    drop = app.query_one("#btn_drop")
                    edit = app.query_one("#btn_edit")

                    self.assertEqual(intercept.variant, "default")
                    self.assertIn("intercept-on", intercept.classes)

                    app.set_intercept_state(True)
                    self.assertIn("forward-ready", forward.classes)
                    self.assertIn("drop-ready", drop.classes)
                    self.assertIn("edit-ready", edit.classes)

                    app.set_intercept_state(False)
                    self.assertNotIn("forward-ready", forward.classes)
                    self.assertNotIn("drop-ready", drop.classes)
                    self.assertNotIn("edit-ready", edit.classes)
            finally:
                os.chdir(previous_cwd)

    async def test_history_search_value_updates_and_clears_visual_search(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                app = NoxenApp(project_args_without_device_scan(os.path.join(tmp, "search.noxen")))
                async with app.run_test(size=(100, 32)) as pilot:
                    app.query_one("#main_tabs").active = "tab_history"
                    await pilot.pause()
                    search = app.query_one("#history_search", Input)

                    search.value = "payment  token"
                    await pilot.pause()

                    self.assertEqual(search.value, "payment  token")
                    self.assertEqual(app._history_search_text, "payment  token")

                    search.value = ""
                    await pilot.pause()

                    self.assertEqual(search.value, "")
                    self.assertEqual(app._history_search_text, "")
            finally:
                os.chdir(previous_cwd)



if __name__ == "__main__":
    unittest.main()
