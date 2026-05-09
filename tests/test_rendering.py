import unittest
from datetime import datetime, timezone

from rich.text import Text

from noxen.rendering import (
    decode_pending_intent_flags,
    entry_to_filter_context,
    filter_sort_history_entries,
    history_row_values,
    history_search_matches,
    history_sort_key,
    payload_to_filter_context,
    payload_to_history_entry,
    render_intercept_block,
    render_intent_detail,
)
from noxen.filters import FilterManager


class RenderingTests(unittest.TestCase):
    def test_entry_to_filter_context_normalizes_missing_values(self):
        entry = {
            "class": "com.example.MainActivity",
            "method": "startActivity",
            "intent": {
                "action": "android.intent.action.VIEW",
                "component": None,
                "categories": ["android.intent.category.DEFAULT"],
            },
        }

        self.assertEqual(
            entry_to_filter_context(entry),
            {
                "class": "com.example.MainActivity",
                "method": "startActivity",
                "action": "android.intent.action.VIEW",
                "component": "",
                "data": "",
                "flags": "0",
                "category": ["android.intent.category.DEFAULT"],
            },
        )

    def test_payload_to_filter_context_normalizes_frida_payload(self):
        payload = {
            "className": "com.example.MainActivity",
            "methodName": "startActivity",
            "infoIntent": {
                "action": "android.intent.action.VIEW",
                "component": None,
                "categories": ["android.intent.category.DEFAULT"],
            },
        }

        self.assertEqual(
            payload_to_filter_context(payload),
            {
                "class": "com.example.MainActivity",
                "method": "startActivity",
                "action": "android.intent.action.VIEW",
                "component": "",
                "data": "",
                "flags": "0",
                "category": ["android.intent.category.DEFAULT"],
            },
        )

    def test_payload_to_history_entry_normalizes_frida_payload(self):
        payload = {
            "className": "com.example.MainActivity",
            "methodName": "startActivity",
            "infoIntent": {"action": "android.intent.action.VIEW"},
            "stackTrace": ["frame1"],
            "pendingIntentFlags": 1,
        }

        entry = payload_to_history_entry(
            payload,
            now=datetime(2026, 4, 28, 10, 11, 12, tzinfo=timezone.utc),
        )

        self.assertEqual(entry, {
            "id": None,
            "timestamp": "2026-04-28T10:11:12+00:00",
            "class": "com.example.MainActivity",
            "method": "startActivity",
            "intent": {"action": "android.intent.action.VIEW"},
            "stackTrace": ["frame1"],
            "pendingIntentFlags": 1,
            "attackSurface": {},
        })

    def test_history_sort_key(self):
        entry = {
            "id": 9,
            "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "Com.Example.MainActivity",
            "method": "StartActivity",
            "outcome": "forwarded",
            "intent": {
                "action": "Android.Intent.Action.View",
                "component": "Com.Example/.Target",
                "extras": {"token": {"type": "string", "value": "abc"}},
            },
        }

        self.assertEqual(history_sort_key(entry, "id"), 9)
        self.assertEqual(history_sort_key(entry, "method"), "startactivity")
        self.assertEqual(history_sort_key(entry, "class"), "com.example.mainactivity")
        self.assertEqual(history_sort_key(entry, "component"), "com.example/.target")
        self.assertEqual(history_sort_key(entry, "action"), "android.intent.action.view")
        self.assertTrue(history_sort_key(entry, "extras"))
        self.assertEqual(history_sort_key(entry, "outcome"), "forwarded")
        self.assertEqual(history_sort_key(entry, "unknown"), "")

    def test_history_search_matches_core_fields_categories_and_extras(self):
        entry = {
            "class": "com.example.MainActivity",
            "method": "startActivity",
            "intent": {
                "action": "android.intent.action.VIEW",
                "component": "com.example/.Target",
                "data": "https://example.test",
                "flags": 123,
                "categories": ["android.intent.category.DEFAULT"],
                "extras": {"token": {"type": "string", "value": "secret-value"}},
            },
        }

        self.assertTrue(history_search_matches(entry, "mainactivity"))
        self.assertTrue(history_search_matches(entry, "default"))
        self.assertTrue(history_search_matches(entry, "token"))
        self.assertTrue(history_search_matches(entry, "secret-value"))
        self.assertFalse(history_search_matches(entry, "missing"))

    def test_filter_sort_history_entries_applies_filters_search_and_sort(self):
        entries = [
            {
                "id": 1,
                "timestamp": "2026-04-28T10:00:00+00:00",
                "class": "com.example.First",
                "method": "getIntent",
                "intent": {"action": "android.intent.action.VIEW", "categories": [], "extras": {}},
            },
            {
                "id": 2,
                "timestamp": "2026-04-28T10:01:00+00:00",
                "class": "com.example.Second",
                "method": "sendBroadcast",
                "intent": {"action": "android.intent.action.SEND", "categories": [], "extras": {}},
            },
            {
                "id": 3,
                "timestamp": "2026-04-28T10:02:00+00:00",
                "class": "com.example.Third",
                "method": "startActivity",
                "intent": {"action": "android.intent.action.VIEW", "categories": [], "extras": {}},
            },
        ]
        filters = FilterManager()
        filters.add("focus", ["action=android.intent.action.VIEW"])

        filtered = filter_sort_history_entries(
            entries,
            filters,
            search_text="example",
            sort_column="id",
            sort_reverse=True,
        )

        self.assertEqual([entry["id"] for entry in filtered], [3, 1])

    def test_history_row_values_respects_visible_columns(self):
        entry = {
            "id": 9,
            "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "com.example.MainActivity",
            "method": "startActivity",
            "outcome": "forwarded",
            "intent": {
                "action": "android.intent.action.VIEW",
                "component": "com.example/.Target",
                "extras": {"token": {"type": "string", "value": "abc"}},
            },
        }
        columns = [
            ("id", "#"),
            ("outcome", "->"),
            ("time", "Time"),
            ("method", "Method"),
            ("extras", "Extras"),
        ]

        values = history_row_values(entry, {"id", "outcome", "time", "extras"}, columns)

        self.assertEqual(values[0], "9")
        self.assertEqual(str(values[1]), "→")
        self.assertEqual(values[2], "2026-04-27 12:34:56")
        self.assertEqual(str(values[3]), "✓")

    def test_decode_pending_intent_flags(self):
        flags = 0x04000000 | 0x10000000
        self.assertEqual(
            decode_pending_intent_flags(flags),
            ["FLAG_CANCEL_CURRENT", "FLAG_IMMUTABLE"],
        )
        self.assertIsNone(decode_pending_intent_flags(None))

    def test_render_intercept_block_includes_stack_limit(self):
        payload = {
            "className": "com.example.MainActivity",
            "methodName": "startActivity",
            "pendingIntentFlags": 0x02000000,
            "stackTrace": ["frame1", "frame2", "frame3"],
            "infoIntent": {
                "action": "android.intent.action.VIEW",
                "component": "com.example/.Target",
                "data": "https://example.test",
                "flags": 1,
                "categories": ["android.intent.category.DEFAULT"],
                "extras": {"x": {"type": "java.lang.String", "value": "y"}},
            },
        }

        rendered = render_intercept_block(payload, 7, show_stack=True, stack_depth=2)

        self.assertIn("INTERCEPTED", rendered)
        self.assertIn("#7", rendered)
        self.assertIn("[#FFB1B1]FLAG_MUTABLE[/#FFB1B1]", rendered)
        self.assertIn("frame1", rendered)
        self.assertIn("frame2", rendered)
        self.assertIn("... (+1 more)", rendered)
        self.assertNotIn("frame3\n", rendered)

    def test_render_intercept_block_escapes_dynamic_markup(self):
        payload = {
            "className": "com.example.[Bad]",
            "methodName": "getIntent",
            "stackTrace": ["DexPathList[nativeLibraryDirectories=[/system/lib64, /system_ext/lib64]]"],
            "infoIntent": {
                "action": "android.intent.action.VIEW",
                "component": "com.example/.Target[/system/lib64]",
                "data": "content://x/[abc]",
                "categories": ["category[/system/lib64]"],
                "extras": {"token[/bad]": {"type": "string", "value": "value[/system/lib64]"}},
            },
        }

        rendered = render_intercept_block(payload, 1, show_stack=True, stack_depth=1)

        Text.from_markup(rendered)
        self.assertIn("\\[/system/lib64", rendered)

    def test_render_intent_detail_includes_changes(self):
        entry = {
            "id": 3,
            "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "com.example.MainActivity",
            "method": "startActivity",
            "outcome": "modified_forwarded",
            "pendingIntentFlags": 0x04000000,
            "intent": {
                "action": "new.action",
                "component": "com.example/.Target",
                "data": "https://new.example",
                "categories": ["new.category"],
                "extras": {
                    "changed": {"type": "string", "value": "new"},
                    "added": {"type": "string", "value": "value"},
                },
            },
            "original_intent": {
                "action": "old.action",
                "data": "https://old.example",
                "categories": ["old.category"],
                "extras": {
                    "changed": {"type": "string", "value": "old"},
                    "removed": {"type": "string", "value": "gone"},
                },
            },
            "stackTrace": ["frame1", "frame2"],
        }

        rendered = render_intent_detail(entry, show_stack=True, stack_depth=1)

        self.assertIn("forwarded (modified)", rendered)
        self.assertIn("old.action", rendered)
        self.assertIn("new.action", rendered)
        self.assertIn("old.category", rendered)
        self.assertIn("new.category", rendered)
        self.assertIn("changed", rendered)
        self.assertIn("removed", rendered)
        self.assertIn("added", rendered)
        self.assertIn("FLAG_IMMUTABLE", rendered)
        self.assertIn("frame1", rendered)
        self.assertIn("... (+1 more)", rendered)

    def test_render_intent_detail_escapes_dynamic_markup(self):
        entry = {
            "id": 9,
            "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "com.example.[Bad]",
            "method": "startActivity",
            "intent": {
                "action": "action[/system/lib64]",
                "component": "component[abc]",
                "data": "content://x/[/system_ext/lib64]",
                "categories": ["category[/system/lib64]"],
                "extras": {"key[/bad]": {"type": "string", "value": "value[/system/lib64]"}},
            },
            "original_intent": {
                "action": "old[/system/lib64]",
                "data": "old-data[/system_ext/lib64]",
                "categories": ["old[/system/lib64]"],
                "extras": {"key[/bad]": {"type": "string", "value": "old[/system/lib64]"}},
            },
            "stackTrace": ["frame[/system/lib64]"],
        }

        rendered = render_intent_detail(entry, show_stack=True, stack_depth=1)

        Text.from_markup(rendered)
        self.assertIn("\\[/system/lib64", rendered)


if __name__ == "__main__":
    unittest.main()
