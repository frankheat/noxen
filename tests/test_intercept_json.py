import copy
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from noxen.app import NoxenApp
from noxen.intent_mods import apply_mods_to_intent
from noxen.intercept_json import apply_mod_to_json, editable_intent, json_to_mods
from tests.ui_test_case import IsolatedAppTestCase


def scalar(java_type, value):
    return {"kind": "scalar", "type": java_type, "value": value}


def extra(node):
    return {"type": node.get("type"), "value": str(node.get("value")), "structuredVersion": 1, "structured": node}


def captured():
    nested = {"kind": "intent", "type": "android.content.Intent", "component": "a.b/a.b.X", "action": "in.ACT",
              "data": None, "mimeType": None, "package": None, "flags": 0, "categories": [],
              "extras": {"kind": "bundle", "type": "android.os.Bundle", "count": 1,
                         "items": [{"key": "k", "value": scalar("java.lang.String", "v")}]},
              "selector": None, "clipData": None}
    return {"component": "test.app/test.app.Receiver", "action": "test.PING", "data": None, "mimeType": None,
            "package": None, "flags": 0x10, "categories": ["c1"], "selector": None, "clipData": None,
            "extrasMeta": {"omitted": 0},
            "extras": {"n": extra(scalar("java.lang.Integer", "3")),
                       "obj": extra({"kind": "object", "type": "test.Custom"}),
                       "inner": extra(nested)}}


class InterceptJsonTests(unittest.TestCase):
    def setUp(self):
        self.captured = captured()
        self.shown, self.notes = editable_intent({"intent": self.captured})

    def mods(self, change):
        edited = copy.deepcopy(self.shown)
        change(edited)
        return json_to_mods(self.captured, self.shown, edited)

    def test_shown_json_leaves_out_what_was_not_captured_and_says_so(self):
        self.assertEqual(self.shown["extras"]["n"], {"type": "int", "value": 3})
        self.assertNotIn("obj", self.shown["extras"])
        self.assertTrue(any("obj" in note and "test.Custom" in note for note in self.notes))
        self.assertEqual(self.mods(lambda edited: None), [])

    def test_only_changed_fields_become_modifications(self):
        self.assertEqual(self.mods(lambda e: e.update(action="X")), [("action", "", "X", "")])
        self.assertEqual(self.mods(lambda e: e.update(component="test.app/.Other")),
                         [("component", "", "test.app/test.app.Other", "")])
        self.assertEqual(self.mods(lambda e: (e.update(flags=0x10000010), e["categories"].append("c2"))),
                         [("cat_add", "", "c2", ""), ("flag_rem", "", "16", ""), ("flag_add", "", "268435472", "")])
        self.assertEqual(self.mods(lambda e: e["extras"]["n"].update(value=4)),
                         [("extra_rem", "n", "", ""), ("extra_add", "n", "4", "int")])
        self.assertEqual(self.mods(lambda e: e["extras"].pop("n")), [("extra_rem", "n", "", "")])
        # A field deleted from the JSON is cleared; the uncaptured extra is never removed.
        self.assertEqual(self.mods(lambda e: e.pop("action")), [("action", "", None, "")])
        self.assertEqual(self.mods(lambda e: e.update(action="")), [("action", "", "", "")])  # Empty, not cleared.
        self.assertNotIn(("extra_rem", "obj", "", ""), self.mods(lambda e: e["extras"].clear()))

    def test_typed_values_are_written_the_way_the_agent_reads_them(self):
        add = lambda key, item: self.mods(lambda e: e["extras"].update({key: item}))  # noqa: E731
        self.assertEqual(add("s", {"type": "String", "value": None}), [("extra_add", "s", "", "null")])
        self.assertEqual(add("l", {"type": "long", "value": "5000000000"}), [("extra_add", "l", "5000000000", "long")])
        self.assertEqual(add("b", {"type": "boolean", "value": False}), [("extra_add", "b", "false", "bool")])
        # Only list items are escaped: a single String is passed as it is.
        self.assertEqual(add("s", {"type": "String", "value": "a,b\\c"}), [("extra_add", "s", "a,b\\c", "string")])
        self.assertEqual(add("a", {"type": "String[]", "value": ["a,b", "c\\d"]}),
                         [("extra_add", "a", "a\\,b,c\\\\d", "string[]")])
        result = apply_mods_to_intent(self.captured, add("a", {"type": "String[]", "value": ["a,b", "c\\d"]}))
        self.assertEqual(result["extras"]["a"]["noxenType"], "string[]")

    def test_invalid_changes_are_refused_with_the_reason(self):
        for change, message in (
            (lambda e: e.update(component="x"), "package/class"),
            (lambda e: e.update(flags=-1), "flags"),
            (lambda e: e.update(categories=["a", "a"]), "duplicate category"),
            (lambda e: e.update(extra=1), "unsupported fields"),
            (lambda e: e["extras"].update(s={"type": "short", "value": 1 << 20}), "short out of range"),
            (lambda e: e["extras"].update(s={"type": "Parcel", "value": 1}), "unsupported type"),
            (lambda e: e.update(package="p", selector={"action": "a"}), "package and selector"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.mods(change)

    def test_any_sender_type_and_structure_is_set_as_a_whole_value(self):
        whole = lambda key, item: ("extra_json", key, json.dumps(item, ensure_ascii=False), "")  # noqa: E731
        short = {"type": "short", "value": 1}
        self.assertEqual(self.mods(lambda e: e["extras"].update(s=short)), [whole("s", short)])
        empty = {"type": "int[]", "value": []}
        self.assertEqual(self.mods(lambda e: e["extras"].update(a=empty)), [whole("a", empty)])
        # A Bundle's contents or a nested Intent's other fields: the extra, captured in full, is rebuilt.
        def nested_flags(e):
            e["extras"]["inner"]["value"].update(flags=1)
        edited = copy.deepcopy(self.shown)
        nested_flags(edited)
        self.assertEqual(self.mods(nested_flags), [whole("inner", edited["extras"]["inner"])])
        self.assertEqual(self.mods(lambda e: e.update(package="p")), [("package", "", "p", "")])
        selector = {"component": "a.b/a.b.S", "action": "s", "flags": 0, "categories": [], "extras": None}
        self.assertEqual(self.mods(lambda e: e.update(selector=selector)),
                         [("selector_json", "", json.dumps(selector), "")])
        # Package is cleared before a selector is set, never together.
        with_package = {**self.shown, "package": "p"}
        mods = json_to_mods({**self.captured, "package": "p"}, with_package,
                            {**with_package, "package": None, "selector": selector})
        self.assertEqual([mod[0] for mod in mods], ["package", "selector_json"])

    def test_values_not_captured_in_full_are_never_replaced_as_a_whole(self):
        captured = self.captured
        captured["extras"]["inner"]["structured"]["extras"]["items"].append(
            {"key": "opaque", "value": {"kind": "object", "type": "x.Y"}})
        captured["extras"]["inner"]["structured"]["extras"]["count"] = 2
        shown, _ = editable_intent({"intent": captured})
        edited = copy.deepcopy(shown)
        edited["extras"]["inner"]["value"]["action"] = "NEW"  # A field: still possible.
        self.assertEqual(json_to_mods(captured, shown, edited), [("nested_action", "inner", "NEW", "")])
        edited["extras"]["inner"]["value"]["flags"] = 1  # The whole Intent: would lose "opaque".
        with self.assertRaisesRegex(ValueError, "not captured in full"):
            json_to_mods(captured, shown, edited)

    def test_fields_of_nested_intents_can_change(self):
        self.assertEqual(self.mods(lambda e: e["extras"]["inner"]["value"].update(action="NEW")),
                         [("nested_action", "inner", "NEW", "")])

    def test_commands_typed_while_editing_change_the_json(self):
        self.assertEqual(apply_mod_to_json(self.shown, ("extra_add", "z", "1,2", "int[]"))["extras"]["z"],
                         {"type": "int[]", "value": [1, 2]})
        self.assertEqual(apply_mod_to_json(self.shown, ("extra_add", "t", "t", "bool"))["extras"]["t"],
                         {"type": "boolean", "value": True})
        self.assertEqual(apply_mod_to_json(self.shown, ("nested_action", "inner", "Q", ""))
                         ["extras"]["inner"]["value"]["action"], "Q")
        self.assertEqual(apply_mod_to_json(self.shown, ("flag_add", "", "0x1", ""))["flags"], 0x11)
        self.assertEqual(apply_mod_to_json(self.shown, ("cat_rem", "", "c1", ""))["categories"], [])
        with self.assertRaisesRegex(ValueError, "cannot be shown in the JSON editor"):
            apply_mod_to_json(self.shown, ("extra_add", "z", "a/b", "component"))
        with self.assertRaisesRegex(ValueError, "not in the JSON"):
            apply_mod_to_json(self.shown, ("nested_action", "missing", "Q", ""))


class InterceptJsonEditorTests(IsolatedAppTestCase):
    async def test_editor_shows_json_reports_errors_forwards_changes_and_escape_cancels(self):
        app = NoxenApp(SimpleNamespace(project=None,
            new_project=str(self.settings_path.parent / "editor.noxen"), skip_device_scan=True))
        self.addCleanup(app.db.close)
        async with app.run_test(size=(120, 45)) as pilot:
            app.query_one("#main_tabs").active = "tab_intercept"
            await pilot.pause()
            app._current_intercepted_entry = {"id": 1, "method": "getIntent", "intent": captured()}
            app._enter_edit_mode()
            await pilot.pause()
            editor = app.query_one("#edit_form")
            self.assertTrue(editor.display)
            self.assertFalse(app.query_one("#intercept_output").display)
            self.assertIs(app.focused, editor.area)
            self.assertEqual(json.loads(editor.area.text)["action"], "test.PING")
            self.assertIn("test.Custom", str(editor.query_one(".json_status").content))
            self.assertFalse(app.check_action("toggle_detail_view", ()))  # Already JSON.

            sent = []
            with patch.object(app, "_apply_mods_and_forward_worker", side_effect=sent.append):
                editor.area.load(editor.area.text.replace('"test.PING",', '"test.PING", oops'))
                app._forward_from_edit_mode()  # What Ctrl+F does while an Intent is held.
                await pilot.pause()
                status = editor.query_one(".json_status")
                self.assertTrue(status.has_class("error"))
                self.assertIn("Line 3", str(status.content))
                self.assertEqual(sent, [])
                editor.area.load(editor.area.text.replace('"test.PING", oops', '"EDITED",'))
                app._forward_from_edit_mode()
                await pilot.pause()
            self.assertEqual(sent, [[("action", "", "EDITED", "")]])

            app._exit_edit_mode()
            app._intent_blocked = True  # Held, so the edit bindings apply.
            app._enter_edit_mode()
            await pilot.pause()
            editor.area.focus()
            await pilot.press("ctrl+space")  # Escape first closes the suggestions...
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            self.assertTrue(app._edit_mode)
            await pilot.press("escape")  # ...then cancels the edit.
            await pilot.pause()
            self.assertFalse(app._edit_mode)
            self.assertTrue(app.query_one("#intercept_output").display)
            self.assertEqual(app._current_intercepted_entry["intent"], captured())


if __name__ == "__main__":
    unittest.main()
