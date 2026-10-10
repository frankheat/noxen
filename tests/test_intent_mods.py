import unittest

from noxen.intent_mods import (
    EXTRA_TYPE_OPTIONS,
    EXTRA_VALUE_PLACEHOLDERS,
    apply_mods_to_entry,
    apply_mods_to_intent,
    diff_intents,
    java_type_display,
    normalize_extra_type,
    parse_flag_value,
    parse_intent_mod_command,
    split_extra_values,
    validate_extra_value,
)


class IntentModsTests(unittest.TestCase):
    def test_apply_mods_to_entry_records_original_snapshot(self):
        entry = {
            "intent": {
                "action": "old.action",
                "data": "content://old",
                "mimeType": "text/plain",
                "flags": 1,
                "categories": ["old.category"],
                "extras": {
                    "token": {"type": "java.lang.String", "value": "old"},
                    "remove_me": {"type": "java.lang.String", "value": "gone"},
                },
            }
        }

        apply_mods_to_entry(entry, [
            ("action", "", "new.action", ""),
            ("data", "", "content://new", ""),
            ("mime", "", "application/pdf", ""),
            ("cat_rem", "", "old.category", ""),
            ("cat_add", "", "new.category", ""),
            ("flag_add", "", "0x10", ""),
            ("extra_rem", "remove_me", "", ""),
            ("extra_add", "token", "new", "string"),
            ("extra_add", "added", "42", "int"),
        ])

        self.assertEqual(entry["original_intent"]["action"], "old.action")
        self.assertEqual(entry["intent"]["action"], "new.action")
        self.assertEqual(entry["intent"]["data"], "content://new")
        self.assertEqual(entry["intent"]["mimeType"], "application/pdf")
        self.assertEqual(entry["intent"]["flags"], 17)
        self.assertEqual(entry["intent"]["categories"], ["new.category"])
        self.assertNotIn("remove_me", entry["intent"]["extras"])
        self.assertEqual(
            entry["intent"]["extras"]["token"],
            {"type": "java.lang.String", "value": "new", "noxenType": "string"},
        )
        self.assertEqual(
            entry["intent"]["extras"]["added"],
            {"type": "java.lang.Integer", "value": "42", "noxenType": "int"},
        )

    def test_apply_mods_to_entry_removes_flags(self):
        entry = {"intent": {"flags": 0x11, "categories": [], "extras": {}}}

        apply_mods_to_entry(entry, [("flag_rem", "", "0x10", "")])

        self.assertEqual(entry["intent"]["flags"], 1)

    def test_apply_mods_to_intent_is_pure_and_diff_round_trips(self):
        original = {
            "action": "old.action",
            "data": None,
            "mimeType": "text/plain",
            "flags": -1,
            "categories": ["old.category", "keep.category"],
            "extras": {
                "keep": {"type": "java.lang.Short", "value": "5"},
                "change": {"type": "java.lang.String", "value": "old"},
                "opaque": {
                    "type": "com.example.Secret", "value": "(opaque object)",
                    "editable": False,
                },
            },
        }
        draft = apply_mods_to_intent(original, [
            ("action", "", "new.action", ""),
            ("data", "", "content://items/1", ""),
            ("mime", "", "application/json", ""),
            ("cat_rem", "", "old.category", ""),
            ("cat_add", "", "new.category", ""),
            ("flag_rem", "", "0x80000000", ""),
            ("extra_rem", "change", "", ""),
            ("extra_add", "change", "1,2,3", "int[]"),
            ("extra_add", "empty", "", "string"),
            ("extra_add", "optional", "", "null"),
        ])

        self.assertEqual(original["action"], "old.action")
        self.assertEqual(original["extras"]["change"]["value"], "old")
        replayed = apply_mods_to_intent(original, diff_intents(original, draft))
        self.assertEqual(replayed, draft)
        self.assertEqual(replayed["mimeType"], "application/json")
        self.assertEqual(replayed["extras"]["keep"]["type"], "java.lang.Short")
        self.assertEqual(replayed["extras"]["opaque"], original["extras"]["opaque"])

    def test_data_and_mime_modifications_preserve_each_other(self):
        original = {
            "data": "content://items/1",
            "mimeType": "text/plain",
            "categories": [],
            "extras": {},
            "flags": 0,
        }

        changed_data = apply_mods_to_intent(
            original,
            [("data", "", "content://items/2", "")],
        )
        changed_mime = apply_mods_to_intent(
            original,
            [("mime", "", "application/pdf", "")],
        )

        self.assertEqual(changed_data["mimeType"], "text/plain")
        self.assertEqual(changed_mime["data"], "content://items/1")
        self.assertEqual(
            diff_intents(original, changed_data),
            [("data", "", "content://items/2", "")],
        )
        self.assertEqual(
            diff_intents(original, changed_mime),
            [("mime", "", "application/pdf", "")],
        )

    def test_diff_treats_signed_and_unsigned_flags_as_the_same_mask(self):
        self.assertEqual(
            diff_intents(
                {"flags": -1, "categories": [], "extras": {}},
                {"flags": 0xFFFFFFFF, "categories": [], "extras": {}},
            ),
            [],
        )

    def test_opaque_extra_can_be_removed_but_is_never_reconstructed(self):
        opaque = {"type": "com.example.Secret", "value": "opaque", "editable": False}
        original = {"categories": [], "extras": {"secret": opaque}, "flags": 0}

        self.assertEqual(
            diff_intents(original, {"categories": [], "extras": {}, "flags": 0}),
            [("extra_rem", "secret", "", "")],
        )
        changed = {"categories": [], "extras": {"secret": {**opaque, "value": "changed"}}, "flags": 0}
        self.assertEqual(diff_intents(original, changed), [])

    def test_java_type_display(self):
        self.assertEqual(java_type_display("java.lang.String"), "String")
        self.assertEqual(java_type_display("android.content.Context$BindServiceFlags"), "BindServiceFlags")
        self.assertEqual(java_type_display(""), "-")

    def test_parse_flag_value(self):
        self.assertEqual(parse_flag_value("16"), 16)
        self.assertEqual(parse_flag_value("0x10"), 16)
        self.assertEqual(parse_flag_value("-2147483648"), -2147483648)
        self.assertEqual(parse_flag_value("0xFFFFFFFF"), 0xFFFFFFFF)
        self.assertIsNone(parse_flag_value("not-an-int"))
        self.assertIsNone(parse_flag_value("-2147483649"))
        self.assertIsNone(parse_flag_value("0x100000000"))

    def test_parse_intent_mod_command(self):
        self.assertEqual(
            parse_intent_mod_command(["action", "android.intent.action.VIEW"]),
            (("action", "", "android.intent.action.VIEW", ""), None),
        )
        self.assertEqual(
            parse_intent_mod_command(["mime", "application/pdf"]),
            (("mime", "", "application/pdf", ""), None),
        )
        self.assertEqual(
            parse_intent_mod_command(["mime", "clear"]),
            (("mime", "", "", ""), None),
        )
        self.assertEqual(
            parse_intent_mod_command(["+x", "string", "token", "hello", "world"]),
            (("extra_add", "token", "hello world", "string"), None),
        )
        self.assertEqual(
            parse_intent_mod_command(["+x", "token", "hello", "world"]),
            (("extra_add", "token", "hello world", "string"), None),
        )
        self.assertEqual(
            parse_intent_mod_command(["-x", "token"]),
            (("extra_rem", "token", "", ""), None),
        )

    def test_parse_every_adb_extra_type(self):
        types_with_values = {
            "string": "hello", "bool": "t", "int": "0x10", "long": "10",
            "float": "1.5", "double": "2.5", "uri": "content://items/1",
            "component": "dev.example/.MainActivity", "int[]": "1,2",
            "long[]": "1,2", "float[]": "1.0,2.0", "double[]": "1.0,2.0",
            "string[]": r"one,two\,three", "int-list": "1,2",
            "long-list": "1,2", "float-list": "1.0,2.0",
            "double-list": "1.0,2.0", "string-list": r"one,two\,three",
        }
        self.assertEqual({value for _label, value in EXTRA_TYPE_OPTIONS}, set(types_with_values) | {"null"})
        self.assertEqual(set(EXTRA_VALUE_PLACEHOLDERS), set(types_with_values) | {"null"})
        self.assertTrue(all("--" not in label for label, _value in EXTRA_TYPE_OPTIONS))
        for extra_type, placeholder in EXTRA_VALUE_PLACEHOLDERS.items():
            with self.subTest(placeholder_for=extra_type):
                self.assertIsNone(validate_extra_value(extra_type, placeholder))
        for extra_type, value in types_with_values.items():
            with self.subTest(extra_type=extra_type):
                self.assertEqual(
                    parse_intent_mod_command(["+x", extra_type, "key", value]),
                    (("extra_add", "key", value, extra_type), None),
                )
        self.assertEqual(
            parse_intent_mod_command(["+x", "null", "key"]),
            (("extra_add", "key", "", "null"), None),
        )

    def test_adb_flag_aliases_are_accepted(self):
        self.assertEqual(normalize_extra_type("--eia"), "int[]")
        self.assertEqual(normalize_extra_type("esal"), "string-list")
        self.assertEqual(normalize_extra_type("boolean"), "bool")

    def test_validate_extra_values(self):
        for value in ("true", "f", "0", "-2", "0x10"):
            self.assertIsNone(validate_extra_value("bool", value))
        self.assertIsNone(validate_extra_value("int", "#7fffffff"))
        self.assertIsNone(validate_extra_value("int[]", "1,-2,0x10"))
        self.assertIsNone(validate_extra_value("long-list", "1,9223372036854775807"))
        self.assertIsNone(validate_extra_value("double[]", "NaN,Infinity,-1.5e2"))
        self.assertIsNone(validate_extra_value("component", "dev.example/.MainActivity"))
        self.assertIsNotNone(validate_extra_value("bool", "yes"))
        self.assertIsNotNone(validate_extra_value("int", "2147483648"))
        self.assertIsNotNone(validate_extra_value("long", "9223372036854775808"))
        self.assertIsNotNone(validate_extra_value("float[]", "1.0,nope"))
        self.assertIsNotNone(validate_extra_value("component", "MainActivity"))

    def test_split_extra_values_supports_escaped_commas_and_backslashes(self):
        self.assertEqual(
            split_extra_values(r"first,comma\,inside,path\\name"),
            ["first", "comma,inside", r"path\name"],
        )

    def test_history_representation_preserves_collection_type_and_null(self):
        entry = {"intent": {"categories": [], "extras": {}}}
        apply_mods_to_entry(entry, [
            ("extra_add", "ids", "1,2", "int[]"),
            ("extra_add", "names", "one,two", "string-list"),
            ("extra_add", "optional", "ignored", "null"),
        ])
        self.assertEqual(entry["intent"]["extras"]["ids"]["type"], "[I")
        self.assertEqual(entry["intent"]["extras"]["ids"]["noxenType"], "int[]")
        self.assertEqual(entry["intent"]["extras"]["names"]["type"], "java.util.ArrayList")
        self.assertEqual(entry["intent"]["extras"]["names"]["noxenType"], "string-list")
        self.assertIsNone(entry["intent"]["extras"]["optional"]["value"])

    def test_parse_intent_mod_command_reports_usage_errors(self):
        self.assertEqual(
            parse_intent_mod_command(["mime"]),
            (None, "[red]Usage: mime <type> | mime clear[/red]"),
        )
        self.assertEqual(
            parse_intent_mod_command(["+flag"]),
            (None, "[red]Usage: +flag <int>[/red]"),
        )
        self.assertEqual(
            parse_intent_mod_command(["+flag", "not-an-int"]),
            (None, "[red]Flag must be a 32-bit integer or bit mask[/red]"),
        )
        self.assertEqual(
            parse_intent_mod_command(["+x"]),
            (None, "[red]Usage: +x [type] <key> <value>[/red]"),
        )
        self.assertEqual(
            parse_intent_mod_command(["+x", "int", "key", "not-an-int"]),
            (None, "[red]Invalid int value: not-an-int[/red]"),
        )
        self.assertEqual(
            parse_intent_mod_command(["+x", "null", "key", "value"]),
            (None, "[red]Usage: +x null <key>[/red]"),
        )


if __name__ == "__main__":
    unittest.main()
