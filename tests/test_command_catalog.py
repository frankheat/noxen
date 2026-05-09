import unittest

from noxen.commands import (
    HISTORY_COMPLETIONS,
    INTENT_COMMAND_BASES,
    INTERCEPT_COMPLETIONS,
    completion_fill_from_prompt,
    format_completion_option,
    matching_completions,
    parse_clear_command,
    parse_command,
    parse_export_command,
    parse_filter_command,
    parse_intent_command,
    parse_intercept_command,
    parse_save_command,
    parse_stack_command,
    parse_theme_command,
    resolve_submitted_command,
)


class CommandCatalogTests(unittest.TestCase):
    def test_history_exposes_only_slash_commands(self):
        commands = [template for template, _desc in HISTORY_COMPLETIONS]

        self.assertTrue(commands)
        self.assertTrue(all(command.startswith("/") for command in commands))
        self.assertIn("/filter add ignore <rule>", commands)
        self.assertIn("/stack <number>", commands)

    def test_intercept_keeps_bare_commands_intent_scoped(self):
        commands = [template for template, _desc in INTERCEPT_COMPLETIONS]
        bare_commands = [command for command in commands if not command.startswith("/")]

        self.assertIn("forward", bare_commands)
        self.assertIn("drop", bare_commands)
        self.assertIn("+x (type) <k> <v>", bare_commands)
        self.assertNotIn("stack on", bare_commands)
        self.assertNotIn("filters", bare_commands)
        self.assertNotIn("ignore <rule>", bare_commands)
        self.assertNotIn("off", bare_commands)

    def test_global_commands_use_slash_namespace(self):
        commands = [template for template, _desc in INTERCEPT_COMPLETIONS]

        self.assertIn("/intercept on", commands)
        self.assertIn("/intercept off", commands)
        self.assertIn("/filter remove <id>", commands)
        self.assertIn("/theme", commands)
        self.assertNotIn("/change theme", commands)

    def test_intent_command_bases_exclude_app_commands(self):
        self.assertIn("forward", INTENT_COMMAND_BASES)
        self.assertIn("+x", INTENT_COMMAND_BASES)
        self.assertNotIn("stack", INTENT_COMMAND_BASES)
        self.assertNotIn("filter", INTENT_COMMAND_BASES)
        self.assertNotIn("off", INTENT_COMMAND_BASES)

    def test_parse_command_normalizes_base(self):
        parsed = parse_command("FoRwArD")

        self.assertEqual(parsed.base, "forward")
        self.assertEqual(parsed.parts, ["FoRwArD"])
        self.assertIsNone(parse_command("   "))

    def test_parse_intent_command_accepts_only_intent_commands(self):
        self.assertEqual(parse_intent_command("+x string token value").base, "+x")
        self.assertIsNone(parse_intent_command("stack on"))
        self.assertIsNone(parse_intent_command("/stack on"))

    def test_parse_stack_command(self):
        self.assertEqual(parse_stack_command(["/stack"]).action, "status")
        self.assertEqual(parse_stack_command(["/stack", "on"]).action, "on")
        depth = parse_stack_command(["/stack", "12"])
        self.assertEqual(depth.action, "depth")
        self.assertEqual(depth.depth, 12)
        self.assertIsNone(parse_stack_command(["/stack", "many"]))

    def test_parse_filter_command(self):
        self.assertEqual(parse_filter_command(["/filter", "list"]).action, "list")

        add = parse_filter_command(["/filter", "add", "ignore", "action=android.intent.action.VIEW"])
        self.assertEqual(add.action, "add")
        self.assertEqual(add.filter_type, "ignore")
        self.assertEqual(add.rule_parts, ["action=android.intent.action.VIEW"])

        remove = parse_filter_command(["/filter", "remove", "7"])
        self.assertEqual(remove.action, "remove")
        self.assertEqual(remove.filter_id, "7")

        self.assertIsNone(parse_filter_command(["/filter", "add", "bad", "a=b"]))
        self.assertIsNone(parse_filter_command(["/filter", "remove"]))

    def test_parse_intercept_command(self):
        self.assertEqual(parse_intercept_command(["/intercept"]).action, "status")
        self.assertEqual(parse_intercept_command(["/intercept", "off"]).action, "off")
        self.assertIsNone(parse_intercept_command(["/intercept", "pause"]))

    def test_parse_export_command(self):
        self.assertFalse(parse_export_command(["/export", "entries"]).filtered)
        self.assertTrue(parse_export_command(["/export", "filtered", "entries"]).filtered)
        self.assertIsNone(parse_export_command(["/export", "filtered"]))

    def test_parse_save_command(self):
        history = parse_save_command(["/save", "history", "filters"])
        self.assertEqual(history.target, "history")
        self.assertEqual(history.file_label, "history_filters")

        intercept = parse_save_command(["/save", "intercept", "filters"])
        self.assertEqual(intercept.target, "intercept")
        self.assertEqual(intercept.file_label, "intercept_filters")

        self.assertIsNone(parse_save_command(["/save", "filters"]))

    def test_parse_theme_command(self):
        self.assertTrue(parse_theme_command(["/theme"]))
        self.assertFalse(parse_theme_command(["/theme", "dark"]))

    def test_parse_clear_command(self):
        parsed = parse_clear_command(["/clear", "history"])
        self.assertEqual(parsed.target, "history")
        self.assertIsNone(parse_clear_command(["/clear"]))
        self.assertIsNone(parse_clear_command(["/clear", "log"]))

    def test_resolve_submitted_command_runs_without_suggestion(self):
        submitted = resolve_submitted_command("  /theme  ", None)

        self.assertFalse(submitted.should_complete)
        self.assertEqual(submitted.command, "/theme")

    def test_resolve_submitted_command_completes_parameterized_suggestion(self):
        submitted = resolve_submitted_command("/filter", "/filter add ")

        self.assertTrue(submitted.should_complete)
        self.assertEqual(submitted.command, "/filter add ")

    def test_resolve_submitted_command_runs_when_suggestion_base_already_matches(self):
        submitted = resolve_submitted_command("/filter add", "/filter add ")

        self.assertFalse(submitted.should_complete)
        self.assertEqual(submitted.command, "/filter add")

    def test_resolve_submitted_command_runs_complete_suggestion(self):
        submitted = resolve_submitted_command("/theme", "/theme")

        self.assertFalse(submitted.should_complete)
        self.assertEqual(submitted.command, "/theme")

    def test_matching_completions_is_case_insensitive(self):
        completions = [("/theme", "Toggle theme"), ("/stack on", "Enable stack")]

        self.assertEqual(matching_completions(completions, "/ST"), [("/stack on", "Enable stack")])
        self.assertEqual(matching_completions(completions, ""), [])

    def test_completion_prompt_roundtrip(self):
        prompt = format_completion_option("/filter add <rule>", "Add filter")

        self.assertEqual(completion_fill_from_prompt(prompt), "/filter add ")


if __name__ == "__main__":
    unittest.main()
