import copy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from rich.text import Text
from textual.widgets import Button

from noxen.app import NoxenApp
from noxen.db import ProjectDB
from noxen.frida_session import FridaSession
from noxen.rendering import (
    entry_to_filter_context, history_search_matches, payload_to_filter_context,
    payload_to_history_entry, render_edit_context, render_intercept_block, render_intent_detail,
)


def payload(present):
    surface = {"callerExported": True}
    if present is not None:
        surface["intentPresent"] = present
    return {"noxenEvent": "intent", "protocolVersion": 1, "className": "example.Service",
            "methodName": "onStartCommand", "infoIntent": {}, "attackSurface": surface,
            "stackTrace": ["example.Service.onStartCommand"],
            "decision": {"required": True, "id": "decision-null"}}


class NullIntentTests(unittest.TestCase):
    def test_only_explicit_absence_hides_payload_fields_in_both_views(self):
        for present in (False, True, None):
            event = payload(present)
            entry = payload_to_history_entry(event)
            entry["id"] = 1
            for rendered in (render_intercept_block(event, 1, True, 1),
                             render_intent_detail(entry, True, 1)):
                text = Text.from_markup(rendered).plain
                self.assertEqual("Intent        : null (no Intent object)" in text, present is False)
                self.assertEqual("Action        : None" in text, present is not False)
                self.assertEqual("Flags         : 0x00000000" in text, present is not False)
                self.assertIn("Exported            : true", text)
                self.assertIn("example.Service.onStartCommand", text)
            self.assertEqual(history_search_matches(entry, "null"), present is False)
            expected_flags = "" if present is False else "0"
            self.assertEqual(entry_to_filter_context(entry)["flags"], expected_flags)
            self.assertEqual(payload_to_filter_context(event)["flags"], expected_flags)

    def test_protocol_marker_is_optional_but_must_be_boolean_and_consistent(self):
        for present in (None, False, True):
            self.assertTrue(FridaSession._valid_intent_event(payload(present)))
        for value in (None, 0, 1, "false", [], {}):
            event = payload(False)
            event["attackSurface"]["intentPresent"] = value
            self.assertFalse(FridaSession._valid_intent_event(event))
        event = payload(False)
        event["infoIntent"] = {"action": "contradictory"}
        self.assertFalse(FridaSession._valid_intent_event(event))

    def test_null_cannot_generate_readonly_editor_context_even_with_stale_fields(self):
        info = {"component": "example/.Stale", "selector": {"kind": "intent"}}
        original = copy.deepcopy(info)
        self.assertEqual(render_edit_context(info, {"intentPresent": False}, "startService"), {})
        self.assertEqual(info, original)

    def test_database_roundtrip_keeps_null_present_and_legacy_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "nulls.noxen")
            db = ProjectDB(path)
            db.create("nulls")
            expected = []
            for present in (False, True, None):
                entry = payload_to_history_entry(payload(present))
                entry["id"] = db.save_intent(entry)
                expected.append(Text.from_markup(render_intent_detail(entry)).plain)
            db.close()
            for _ in range(2):
                db = ProjectDB(path)
                entries = db.open_existing()
                db.close()
                self.assertEqual([entry["attackSurface"].get("intentPresent") for entry in entries],
                                 [False, True, None])
                self.assertEqual([Text.from_markup(render_intent_detail(entry)).plain for entry in entries], expected)
                self.assertNotIn("intentPresent", entries[-1]["attackSurface"])


class NullIntentUITests(unittest.IsolatedAsyncioTestCase):
    async def test_null_disables_editor_and_commands_but_not_forward_or_drop(self):
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(new_project=str(Path(directory) / "ui.noxen"),
                                         project=None, skip_device_scan=True))
            async with app.run_test(size=(110, 40)) as pilot:
                app.query_one("#main_tabs").active = "tab_intercept"
                entry = payload_to_history_entry(payload(False))
                entry["id"] = 1
                app._all_intents.append(entry)
                app._on_intercept_display("", 1, "decision-null")
                app.set_intercept_state(True)
                await pilot.pause()
                for theme in ("noxen-dark", "noxen-light"):
                    app.theme = theme
                    self.assertTrue(app.query_one("#btn_edit", Button).disabled)
                    self.assertFalse(app.query_one("#btn_forward", Button).disabled)
                    self.assertFalse(app.query_one("#btn_drop", Button).disabled)
                    app._enter_edit_mode()
                    self.assertFalse(app._edit_mode)
                messages = []
                app.write_cmd = messages.append
                app.frida_session = SimpleNamespace(is_ready=lambda: True, cleanup=lambda: None)
                for command in ("action changed", "data content://example", "mime text/plain",
                                "+cat example", "+flag 1", "+x key value", "-x key"):
                    NoxenApp.process_command_worker.__wrapped__(app, command)
                    self.assertEqual(app._staged_mods, [])
                    self.assertIn("Intent is null", messages[-1])
                entry["attackSurface"]["intentPresent"] = True
                app._on_intercept_display("", 1, "decision-present")
                await pilot.pause()
                self.assertFalse(app.query_one("#btn_edit", Button).disabled)
                app._enter_edit_mode()
                await pilot.pause()
                self.assertTrue(app._edit_mode)
                app._exit_edit_mode()
                await pilot.pause()
                del entry["attackSurface"]["intentPresent"]
                app._enter_edit_mode()
                await pilot.pause()
                self.assertTrue(app._edit_mode)  # no inference about legacy captures
                app._exit_edit_mode()
                await pilot.pause()
