import unittest

from noxen.intent_mods import (
    apply_mods_to_entry,
    java_type_display,
    parse_flag_value,
    parse_intent_mod_command,
)


class IntentModsTests(unittest.TestCase):
    def test_apply_mods_to_entry_records_original_snapshot(self):
        entry = {
            "intent": {
                "action": "old.action",
                "data": "content://old",
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
        self.assertEqual(entry["intent"]["flags"], 17)
        self.assertEqual(entry["intent"]["categories"], ["new.category"])
        self.assertNotIn("remove_me", entry["intent"]["extras"])
        self.assertEqual(
            entry["intent"]["extras"]["token"],
            {"type": "java.lang.String", "value": "new"},
        )
        self.assertEqual(
            entry["intent"]["extras"]["added"],
            {"type": "int", "value": "42"},
        )

    def test_apply_mods_to_entry_removes_flags(self):
        entry = {"intent": {"flags": 0x11, "categories": [], "extras": {}}}

        apply_mods_to_entry(entry, [("flag_rem", "", "0x10", "")])

        self.assertEqual(entry["intent"]["flags"], 1)

    def test_java_type_display(self):
        self.assertEqual(java_type_display("java.lang.String"), "String")
        self.assertEqual(java_type_display("android.content.Context$BindServiceFlags"), "BindServiceFlags")
        self.assertEqual(java_type_display(""), "-")

    def test_parse_flag_value(self):
        self.assertEqual(parse_flag_value("16"), 16)
        self.assertEqual(parse_flag_value("0x10"), 16)
        self.assertIsNone(parse_flag_value("not-an-int"))

    def test_parse_intent_mod_command(self):
        self.assertEqual(
            parse_intent_mod_command(["action", "android.intent.action.VIEW"]),
            (("action", "", "android.intent.action.VIEW", ""), None),
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

    def test_parse_intent_mod_command_reports_usage_errors(self):
        self.assertEqual(
            parse_intent_mod_command(["+flag"]),
            (None, "[red]Usage: +flag <int>[/red]"),
        )
        self.assertEqual(
            parse_intent_mod_command(["+flag", "not-an-int"]),
            (None, "[red]Flag must be an integer[/red]"),
        )
        self.assertEqual(
            parse_intent_mod_command(["+x"]),
            (None, "[red]Usage: +x (type) <key> <value>[/red]"),
        )


if __name__ == "__main__":
    unittest.main()
