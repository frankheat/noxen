import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rich.text import Text
from textual.widgets import Input, Static

from noxen.app import NoxenApp
from noxen.commands import INTERCEPT_COMPLETIONS, parse_intent_command
from noxen.exporting import write_history_export
from noxen.frida_session import ModificationResume
from noxen.intent_mods import (
    apply_mods_to_intent, confirmed_modification, diff_intents,
    normalize_component, parse_intent_mod_command,
)
from noxen.rendering import history_search_matches, render_intent_detail
from tests import test_modification_confirmation as confirmation_tests
from tests.ui_test_case import IsolatedAppTestCase


def intent():
    return {"component": "example/example.Old", "action": "TEST", "data": None,
            "mimeType": None, "flags": 0, "categories": [], "extras": {},
            "selector": {"kind": "intent", "component": "example/example.Selector", "flags": 0},
            "clipData": {"kind": "clipdata", "count": 0, "items": []}, "package": "example"}


class ComponentModificationTests(unittest.TestCase):
    def test_normalization_and_command_catalog(self):
        for value, expected in (("example/.Target", "example/example.Target"),
                                ("example/other.pkg.Target$Inner", "example/other.pkg.Target$Inner"),
                                ("example/Target", "example/Target"), ("", "")):
            self.assertEqual(normalize_component(value), expected)
        self.assertEqual(parse_intent_mod_command(["component", "example/.Target"]),
                         (("component", "", "example/example.Target", ""), None))
        self.assertEqual(parse_intent_mod_command(["component", "clear"]),
                         (("component", "", "", ""), None))
        self.assertIsNotNone(parse_intent_command("component example/.Target"))
        self.assertTrue(any("component clear" in text for text in INTERCEPT_COMPLETIONS))

    def test_bad_names_and_extra_arguments_are_rejected_without_existence_checks(self):
        for value in ("missingSlash", "/Class", "pkg/", "pkg/A/B", "pkg/.", "pkg/A B", "pkg/A\x00B"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_component(value)
                self.assertIsNotNone(parse_intent_mod_command(["component", value])[1])
        self.assertIsNotNone(parse_intent_mod_command(["component", "pkg/A", "extra"])[1])
        self.assertIsNone(parse_intent_mod_command(["component", "not.installed/.Missing"])[1])

    def test_draft_diff_is_canonical_and_does_not_touch_selector_clip_or_package(self):
        original = intent()
        before = copy.deepcopy(original)
        draft = apply_mods_to_intent(original, [("component", "", "other/.Target", "")])
        self.assertEqual(original, before)
        self.assertEqual(diff_intents(original, draft), [("component", "", "other/other.Target", "")])
        for key in ("selector", "clipData", "package", "extras"):
            self.assertEqual(draft[key], original[key])
        cleared = apply_mods_to_intent(draft, [("component", "", "", "")])
        self.assertIsNone(cleared["component"])
        self.assertEqual(cleared["selector"], original["selector"])
        self.assertEqual(diff_intents(original, {**original, "component": "example/.Old"}), [])

    def test_component_change_requires_an_observed_component_not_a_prediction(self):
        original = intent()
        for actual in ({k: v for k, v in original.items() if k != "component"},
                       {**original, "component": {"invalid": True}}):
            result, changed, error = confirmed_modification(original, {"ok": True, "infoIntent": actual},
                                                            require_component=True)
            self.assertIsNone(result)
            self.assertFalse(changed)
            self.assertIn("could not be verified", error)
        actual = {**original, "component": "other/other.Target"}
        result, changed, error = confirmed_modification(original, {"ok": True, "infoIntent": actual})
        self.assertEqual(result, actual)
        self.assertTrue(changed)
        self.assertIsNone(error)
        self.assertFalse(confirmed_modification(original, {"ok": True, "infoIntent": original})[1])

    def test_confirmed_component_only_forward_clear_persistence_search_and_export(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "component.noxen")
            app, entry, _ = confirmation_tests.ModificationConfirmationTests.make_app(self, path)
            try:
                for value in ("other/other.Target", None):
                    original = copy.deepcopy(entry["intent"])
                    actual = {**original, "component": value}
                    NoxenApp._finalize_forward(app, entry["id"], entry,
                        [("component", "", value or "", "")],
                        ModificationResume(True, {"ok": True, "infoIntent": actual}))
                    self.assertEqual(entry["outcome"], "modified_forwarded")
                    self.assertEqual(entry["original_intent"], original)
                    stored = app.db._load_all()[0]
                    self.assertEqual(stored["intent"]["component"], value)
                    self.assertEqual(stored["original_intent"], original)
                    self.assertIn("[CHANGES]", Text.from_markup(render_intent_detail(stored)).plain)
                    if value:
                        self.assertTrue(history_search_matches(stored, "other.Target"))
                    export = str(Path(directory) / "export.json")
                    with patch("noxen.exporting.timestamped_filename", return_value=export):
                        write_history_export([stored])
                    self.assertEqual(json.loads(Path(export).read_text())[0]["intent"]["component"], value)
                app.db.close()
                self.assertIsNone(app.db.open_existing()[0]["intent"]["component"])
            finally:
                app.db.close()

    def test_stale_component_metadata_is_not_attached_to_a_new_component(self):
        entry = {"id": 1, "class": "example.Receiver", "method": "onReceive", "intent": intent(),
                 "attackSurface": {"callerExported": True,
                     "broadcastComponents": {"base": {"component": "example/example.Old", "exported": False,
                        "permission": {"name": "OLD.PERMISSION", "level": "signature"}}}}}
        entry["intent"]["component"] = "other/other.Target"
        text = Text.from_markup(render_intent_detail(entry)).plain
        self.assertIn("Class         : example.Receiver", text)
        self.assertIn("Exported            : true", text)
        self.assertIn("unavailable", text)
        self.assertNotIn("OLD.PERMISSION", text)


class ComponentEditorTests(IsolatedAppTestCase):
    async def test_editor_commands_validation_metadata_and_cancel_in_both_themes(self):
        app = NoxenApp(SimpleNamespace(project=None,
            new_project=str(self.settings_path.parent / "editor.noxen"), skip_device_scan=True))
        self.addCleanup(app.db.close)
        async with app.run_test(size=(120, 50)) as pilot:
            app.query_one("#main_tabs").active = "tab_intercept"
            for theme in ("noxen-dark", "noxen-light"):
                app.theme = theme
                for method in ("startActivity", "getIntent", "onReceive", "getActivity", "onStartCommand"):
                    with self.subTest(theme=theme, method=method):
                        app._current_intercepted_entry = {"id": 1, "method": method, "intent": intent(),
                            "attackSurface": {"activityComponents": {"base": {
                                "component": "example/example.Old", "exported": True,
                                "permission": {"name": "OLD.PERMISSION", "level": "signature"}}}}}
                        app._enter_edit_mode()
                        await pilot.pause()
                        field = app.query_one("#ef_component", Input)
                        details = app.query_one("#ef_component_body", Static)
                        self.assertEqual(field.value, "example/example.Old")
                        self.assertIn("OLD.PERMISSION", str(details.render()))
                        field.value = "other/.Target"
                        await pilot.pause()
                        self.assertNotIn("OLD.PERMISSION", str(details.render()))
                        self.assertIn("unavailable", str(details.render()))
                        draft = app._collect_edit_draft()
                        self.assertEqual(draft["component"], "other/other.Target")
                        self.assertEqual(draft["selector"], intent()["selector"])
                        mod, _ = parse_intent_mod_command(["component", "clear"])
                        self.assertIsNone(app._apply_command_mod_to_editor(mod))
                        await pilot.pause()
                        self.assertEqual(field.value, "")
                        self.assertIsNone(app._collect_edit_draft()["component"])
                        field.value = "bad name"
                        with self.assertRaisesRegex(ValueError, "package/class"):
                            app._collect_edit_mods()
                        app._exit_edit_mode()
                        self.assertEqual(app._current_intercepted_entry["intent"], intent())
            app._current_intercepted_entry = None
