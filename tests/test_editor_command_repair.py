import copy
from types import SimpleNamespace
from unittest.mock import patch

from textual.widgets import Input, Select

from noxen.app import NoxenApp
from noxen.intent_mods import parse_intent_mod_command
from tests.test_component_editing import intent
from tests.ui_test_case import IsolatedAppTestCase


class EditorCommandRepairTests(IsolatedAppTestCase):
    def make_app(self):
        app = NoxenApp(SimpleNamespace(project=None,
            new_project=str(self.settings_path.parent / "repair.noxen"), skip_device_scan=True))
        self.addCleanup(app.db.close)
        return app

    async def open_editor(self, app, pilot):
        app.query_one("#main_tabs").active = "tab_intercept"
        original = intent()
        original["categories"] = ["example.CATEGORY"]
        original["extras"] = {"count": {"type": "int", "value": "3", "noxenType": "int"}}
        app._current_intercepted_entry = {"id": 7, "class": "Example", "method": "getIntent", "intent": original}
        app._current_intercept_id = 7
        app._enter_edit_mode()
        await pilot.pause()
        return copy.deepcopy(original)

    def raw_state(self, app):
        return (
            [(w.id, w.value) for w in app.query(Input)],
            [(w.id, w.value) for w in app.query(Select)],
            copy.deepcopy(app._edit_cat_rows), copy.deepcopy(app._edit_extra_rows),
            copy.deepcopy(app._edit_display_info), copy.deepcopy(app._current_intercepted_entry),
        )

    def command(self, app, text):
        mod, error = parse_intent_mod_command(text.split())
        self.assertIsNone(error)
        return app._apply_command_mod_to_editor(mod)

    async def test_component_commands_repair_invalid_input_through_the_real_command_worker(self):
        app = self.make_app()
        async with app.run_test(size=(120, 45)) as pilot:
            original = await self.open_editor(app, pilot)
            app.frida_session = SimpleNamespace(is_ready=lambda: True, cleanup=lambda: None)
            for text, expected in (
                ("component dev.noxen.playground/.Activity2", "dev.noxen.playground/dev.noxen.playground.Activity2"),
                ("component dev.noxen.playground/dev.noxen.playground.Activity1", "dev.noxen.playground/dev.noxen.playground.Activity1"),
                ("component clear", ""),
            ):
                app.query_one("#ef_component", Input).value = "invalid component"
                app.query_one("#ef_action", Input).value = "UNSAVED_ACTION"
                await app.process_command_worker(text).wait()
                await pilot.pause()
                self.assertEqual(app.query_one("#ef_component", Input).value, expected)
                self.assertEqual(app.query_one("#ef_action", Input).value, "UNSAVED_ACTION")
                self.assertEqual(app._collect_edit_draft()["selector"], original["selector"])
                self.assertEqual(app._current_intercepted_entry["intent"], original)
            app._exit_edit_mode()
            app._enter_edit_mode()
            await pilot.pause()
            self.assertEqual(app._collect_edit_draft()["component"], original["component"])

    async def test_invalid_result_or_another_invalid_field_leaves_every_input_unchanged(self):
        app = self.make_app()
        async with app.run_test(size=(120, 45)) as pilot:
            await self.open_editor(app, pilot)
            app.query_one("#ef_component", Input).value = "broken"
            app.query_one("#ef_flags", Input).value = "not-a-mask"
            app.query_one("#ef_action", Input).value = "UNSAVED_ACTION"
            before = self.raw_state(app)
            with patch.object(app, "_populate_edit_form", wraps=app._populate_edit_form) as populate:
                error = self.command(app, "component example/.Correct")
                self.assertIn("Flags", error)
                populate.assert_not_called()
            self.assertEqual(self.raw_state(app), before)
            app.query_one("#ef_flags", Input).value = "0"
            before = self.raw_state(app)
            error = app._apply_command_mod_to_editor(("component", "", "still invalid", ""))
            self.assertIn("package/class", error)
            self.assertEqual(self.raw_state(app), before)

    async def test_removing_an_invalid_extra_removes_its_value_before_validation(self):
        app = self.make_app()
        async with app.run_test(size=(120, 45)) as pilot:
            original = await self.open_editor(app, pilot)
            row = next(iter(app._edit_extra_rows))
            app.query_one(f"#ef_xv_{row}", Input).value = "not-an-int"
            app.query_one("#ef_data", Input).value = "content://unsaved"
            self.assertIsNone(self.command(app, "-x count"))
            await pilot.pause()
            draft = app._collect_edit_draft()
            self.assertNotIn("count", draft["extras"])
            self.assertEqual(draft["data"], "content://unsaved")
            self.assertEqual(app._current_intercepted_entry["intent"], original)

    async def test_replacing_an_invalid_and_duplicated_extra_validates_one_final_value(self):
        app = self.make_app()
        async with app.run_test(size=(120, 45)) as pilot:
            await self.open_editor(app, pilot)
            row = next(iter(app._edit_extra_rows))
            app.query_one(f"#ef_xv_{row}", Input).value = "bad"
            app._add_edit_extra_row("after", "string", "keep", is_new=True)
            app._add_edit_extra_row("count", "int", "also-bad", is_new=True)
            await pilot.pause()
            self.assertIsNone(self.command(app, "+x int count 5"))
            await pilot.pause()
            draft = app._collect_edit_draft()
            self.assertEqual(list(draft["extras"]), ["count", "after"])
            self.assertEqual(draft["extras"]["count"]["value"], "5")
            self.assertEqual(draft["extras"]["after"]["value"], "keep")
            self.assertEqual(len(app._edit_extra_rows), 2)
            app.query_one(f"#ef_xv_{next(iter(app._edit_extra_rows))}", Input).value = "bad again"
            before = self.raw_state(app)
            error = app._apply_command_mod_to_editor(("extra_add", "count", "invalid", "int"))
            self.assertIn("Invalid int", error)
            self.assertEqual(self.raw_state(app), before)

    async def test_extra_repair_does_not_ignore_another_invalid_extra(self):
        app = self.make_app()
        async with app.run_test(size=(120, 45)) as pilot:
            await self.open_editor(app, pilot)
            app._add_edit_extra_row("other", "int", "invalid", is_new=True)
            await pilot.pause()
            before = self.raw_state(app)
            error = self.command(app, "+x int count 5")
            self.assertIn("other: Invalid int", error)
            self.assertEqual(self.raw_state(app), before)

    async def test_removing_a_duplicated_category_repairs_the_result_but_adding_does_not(self):
        app = self.make_app()
        async with app.run_test(size=(120, 45)) as pilot:
            await self.open_editor(app, pilot)
            app._add_edit_category_row("example.CATEGORY")
            await pilot.pause()
            before = self.raw_state(app)
            self.assertIn("Duplicate category", self.command(app, "+cat example.OTHER"))
            self.assertEqual(self.raw_state(app), before)
            self.assertIsNone(self.command(app, "-cat example.CATEGORY"))
            await pilot.pause()
            self.assertEqual(app._collect_edit_draft()["categories"], [])

    async def test_relative_flag_commands_require_a_valid_existing_mask(self):
        app = self.make_app()
        async with app.run_test(size=(120, 45)) as pilot:
            await self.open_editor(app, pilot)
            app.query_one("#ef_flags", Input).value = "invalid"
            before = self.raw_state(app)
            for command in ("+flag 1", "-flag 1"):
                self.assertIn("Flags", self.command(app, command))
                self.assertEqual(self.raw_state(app), before)
