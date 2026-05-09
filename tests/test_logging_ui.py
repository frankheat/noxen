import unittest

from rich.text import Text

from noxen.logging_ui import is_debug_log, log_debug, log_error, log_info, log_success, log_warning


class LoggingUiTests(unittest.TestCase):
    def test_log_lines_have_consistent_source_level_message_shape(self):
        self.assertEqual(log_info("Ready", "noxen"), "[dim]noxen        [/dim] [dim]INFO [/dim] Ready")
        self.assertEqual(log_debug("Loaded", "loader"), "[dim]loader       [/dim] [dim]DEBUG[/dim] Loaded")
        self.assertEqual(log_success("Attached", "frida"), "[dim]frida        [/dim] [#26a368]OK   [/#26a368] Attached")
        self.assertEqual(log_warning("Skipped", "agent"), "[dim]agent        [/dim] [yellow]WARN [/yellow] Skipped")
        self.assertEqual(log_error("Failed", "agent"), "[dim]agent        [/dim] [red]ERROR[/red] Failed")

    def test_debug_log_detection(self):
        self.assertTrue(is_debug_log(log_debug("Loaded", "loader")))
        self.assertFalse(is_debug_log(log_info("Ready", "noxen")))

    def test_dynamic_log_message_is_markup_escaped(self):
        message = (
            "ClassNotFoundException: DexPathList[[zip file \"/data/app/base.apk\"],"
            "nativeLibraryDirectories=[/system/lib64, /system_ext/lib64]]"
        )
        line = log_error(message, "agent")

        Text.from_markup(line)
        self.assertIn("\\[/system/lib64", line)


if __name__ == "__main__":
    unittest.main()
