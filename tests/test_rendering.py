import unittest
from datetime import datetime, timezone

from rich.text import Text

from noxen.rendering import (
    decode_intent_flags,
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


def plain(rendered: str) -> str:
    """Visible text of rendered markup: layout assertions don't depend on styling."""
    return Text.from_markup(rendered).plain


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

    def test_decode_intent_flags_includes_combinations_aliases_and_signed_values(self):
        flags = 0x10000000 | 0x04000000
        self.assertEqual(
            decode_intent_flags(flags),
            [
                "FLAG_ACTIVITY_CLEAR_TOP / FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT",
                "FLAG_ACTIVITY_NEW_TASK / FLAG_RECEIVER_FOREGROUND",
            ],
        )
        self.assertIn("FLAG_IGNORE_EPHEMERAL / FLAG_RECEIVER_OFFLOAD", decode_intent_flags(-2147483648))
        self.assertEqual(decode_intent_flags(None), None)

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

        Text.from_markup(rendered)
        self.assertIn("INTERCEPTED #7", rendered)
        self.assertIn("FLAG_MUTABLE", rendered)
        self.assertIn("0x00000001", rendered)
        self.assertIn("FLAG_GRANT_READ_URI_PERMISSION", rendered)
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

    def test_render_intercept_block_sections_and_receiver_tree(self):
        payload = {
            "className": "com.example.Receiver2",
            "methodName": "onReceive",
            "stackTrace": [],
            "attackSurface": {"callerExported": True, "callerPermission": {"name": "com.x.PERM", "level": "signature"}},
            "infoIntent": {},
        }

        rendered = render_intercept_block(payload, 1, show_stack=False, stack_depth=1)

        Text.from_markup(rendered)
        self.assertIn("[bold]\\[HOOK][/bold]", rendered)
        self.assertIn("[bold]\\[CAPTURED INTENT PAYLOAD][/bold]", rendered)
        # Receiving: the exposed component's tree hangs under Class.
        self.assertIn("  Class         : com.example.Receiver2", plain(rendered))
        self.assertIn("                  ├─ Exported            : true", plain(rendered))
        self.assertIn("                  └─ Required Permission : com.x.PERM (signature)", plain(rendered))
        # No Type row on a receiving capture.
        self.assertNotIn("Type ", rendered)

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
                "flags": 0x10000000,
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

        Text.from_markup(rendered)
        self.assertIn("| MODIFIED", plain(rendered))
        self.assertIn("old.action", rendered)
        self.assertIn("new.action", rendered)
        self.assertIn("old.category", rendered)
        self.assertIn("new.category", rendered)
        self.assertIn("changed", rendered)
        self.assertIn("removed", rendered)
        self.assertIn("added", rendered)
        self.assertIn("FLAG_IMMUTABLE", rendered)
        self.assertIn("FLAG_ACTIVITY_NEW_TASK", rendered)
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

    def test_render_intent_detail_receiving_tree(self):
        entry = {
            "id": 10,
            "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "com.example.Activity1",
            "method": "getIntent",
            "intent": {},
            "attackSurface": {"callerExported": False},
            "stackTrace": [],
        }

        rendered = render_intent_detail(entry, show_stack=False, stack_depth=1)

        Text.from_markup(rendered)
        self.assertIn("#10 | 2026-04-27 12:34:56 | PENDING", plain(rendered))
        self.assertIn("  Class         : com.example.Activity1", plain(rendered))
        self.assertIn("                  └─ Exported            : false", plain(rendered))
        self.assertNotIn("Required Permission", rendered)  # omitted when none

    def test_render_intent_detail_sending_target_tree(self):
        entry = {
            "id": 7,
            "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "com.example.MainActivity",
            "method": "sendBroadcast",
            "intent": {"component": "com.example/.Receiver2"},
            "attackSurface": {
                "intentExplicit": True,
                "targetComponent": "com.example/.Receiver2",
                "targetExported": True,
                "targetPermission": {"name": "com.x.PERM", "level": "normal"},
                "broadcastPermission": {"name": "com.x.PERM", "level": "normal"},
            },
            "stackTrace": [],
        }

        rendered = render_intent_detail(entry, show_stack=False, stack_depth=1)

        Text.from_markup(rendered)
        self.assertIn("  Type          : EXPLICIT", plain(rendered))
        self.assertIn("  Target        : com.example/.Receiver2", plain(rendered))
        self.assertIn("                  ├─ Exported            : true", plain(rendered))
        self.assertIn("                  └─ Required Permission : com.x.PERM (normal)", plain(rendered))
        self.assertIn("  Enforced Perm : com.x.PERM (normal)", plain(rendered))

    def test_render_intent_detail_target_states(self):
        base = {
            "id": 1, "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "com.example.MainActivity", "method": "startActivity", "stackTrace": [],
            "intent": {},
        }
        implicit_multi = dict(base, attackSurface={"intentExplicit": False, "targetReceiverCount": 3})
        self.assertIn("  Target        : (resolved) 3 receivers", plain(render_intent_detail(implicit_multi)))

        unresolved = dict(base, attackSurface={"intentExplicit": False})
        self.assertIn("  Target        : (unresolved)", plain(render_intent_detail(unresolved)))

        unreadable = dict(base, attackSurface={
            "intentExplicit": True, "targetComponent": "com.other/.X", "targetUnreadable": True,
        })
        self.assertIn("  Target        : com.other/.X (couldn't read — not visible)", plain(render_intent_detail(unreadable)))

        resolved_single = dict(base, attackSurface={
            "intentExplicit": False, "targetComponent": "com.example/.Activity8",
            "targetResolved": True, "targetExported": True,
        })
        self.assertIn("  Target        : com.example/.Activity8 (resolved)", plain(render_intent_detail(resolved_single)))

    def test_implicit_intent_scope_and_package_row(self):
        base = {
            "id": 1, "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "com.example.MainActivity", "method": "sendBroadcast", "stackTrace": [],
            "attackSurface": {"intentExplicit": False, "targetType": "receiver"},
        }
        open_to_all = dict(base, intent={"action": "com.example.PING", "package": None})
        scoped = dict(base, intent={"action": "com.example.PING", "package": "com.example"})
        legacy = dict(base, intent={"action": "com.example.PING"})  # captured before the package was recorded

        self.assertIn("  Type          : IMPLICIT (any app)", plain(render_intent_detail(open_to_all)))
        self.assertNotIn("Package", plain(render_intent_detail(open_to_all)))
        self.assertIn("  Type          : IMPLICIT (package-scoped)", plain(render_intent_detail(scoped)))
        self.assertIn("  Package       : com.example", plain(render_intent_detail(scoped)))
        legacy_text = plain(render_intent_detail(legacy))
        self.assertIn("  Type          : IMPLICIT\n", legacy_text)  # no guess for old captures

    def test_explicit_intent_type_is_unqualified(self):
        entry = {
            "id": 1, "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "com.example.MainActivity", "method": "startActivity", "stackTrace": [],
            "intent": {"component": "com.example/.A", "package": None},
            "attackSurface": {"intentExplicit": True, "targetComponent": "com.example/.A", "targetType": "activity"},
        }
        self.assertIn("  Type          : EXPLICIT\n", plain(render_intent_detail(entry)))

    def test_broadcast_without_manifest_receiver_is_not_called_unresolved(self):
        base = {
            "id": 1, "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "com.example.MainActivity", "stackTrace": [], "intent": {"package": None},
        }
        broadcast = dict(base, method="sendBroadcast",
                         attackSurface={"intentExplicit": False, "targetType": "receiver"})
        text = plain(render_intent_detail(broadcast))
        self.assertIn("  Target        : (no manifest receiver) — dynamic receivers are not visible", text)
        self.assertNotIn("(unresolved)", text)
        # activities have no runtime-registered handlers: "unresolved" stays accurate
        activity = dict(base, method="startActivity",
                        attackSurface={"intentExplicit": False, "targetType": "activity"})
        self.assertIn("  Target        : (unresolved)", plain(render_intent_detail(activity)))

    def test_detail_grey_scale_dims_labels_not_values(self):
        entry = {
            "id": 3, "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "com.example.MainActivity", "method": "sendBroadcast", "stackTrace": [],
            "intent": {"action": "a.B", "extras": {"k": {"type": "java.lang.String", "value": "v"}}},
            "attackSurface": {"intentExplicit": True, "targetComponent": "com.example/.R",
                              "targetExported": True, "targetResolved": True},
        }
        rendered = render_intent_detail(entry)
        self.assertIn("  [dim]Action        :[/dim] a.B", rendered)
        self.assertIn("[dim]└─ Exported            :[/dim] true", rendered)
        self.assertIn("com.example/.R [dim](resolved)[/dim]", rendered)
        self.assertIn("k [String] : \"v\"", plain(rendered))
        self.assertIn('"v"', rendered)
        dim_text = "".join(
            plain(rendered)[span.start:span.end]
            for span in Text.from_markup(rendered).spans if "dim" in str(span.style)
        )
        self.assertNotIn("a.B", dim_text)  # values keep full brightness

    def test_structured_extras_render_as_bounded_static_tree(self):
        entry = {
            "id": 11,
            "timestamp": "2026-10-07T08:00:00+00:00",
            "class": "com.example.MainActivity",
            "method": "startActivity",
            "intent": {
                "extras": {
                    "user_id": {
                        "type": "java.lang.Integer", "value": "42", "noxenType": "int",
                        "structured": {
                            "kind": "scalar", "type": "java.lang.Integer",
                            "displayType": "int", "noxenType": "int", "value": "42",
                        },
                    },
                    "options": {
                        "type": "android.os.Bundle", "value": "Bundle (2 items)",
                        "structured": {
                            "kind": "bundle", "type": "android.os.Bundle", "displayType": "Bundle",
                            "count": 2, "items": [
                                {"key": "retry", "value": {
                                    "kind": "scalar", "type": "java.lang.Boolean",
                                    "displayType": "boolean", "noxenType": "bool", "value": "true",
                                }},
                                {"key": "next", "value": {
                                    "kind": "intent", "type": "android.content.Intent", "displayType": "Intent",
                                    "action": "com.example.OPEN", "component": "com.example/.DetailActivity",
                                    "data": None, "flags": 1, "categories": [],
                                    "extras": {
                                        "kind": "bundle", "type": "android.os.Bundle", "displayType": "Bundle",
                                        "count": 1, "items": [{"key": "account", "value": {
                                            "kind": "opaque", "type": "com.example.Account",
                                            "displayType": "com.example.Account",
                                        }}],
                                    },
                                }},
                            ],
                        },
                    },
                },
                "extrasMeta": {"count": 4, "capturedCount": 2, "omitted": 2},
            },
            "stackTrace": [],
        }

        rendered = render_intent_detail(entry)
        visible = plain(rendered)

        Text.from_markup(rendered)
        self.assertIn("[EXTRAS] (4)", visible)
        self.assertIn("├─ user_id [int] : 42", visible)
        self.assertIn("└─ next [Intent]", visible)
        self.assertIn("Action        : com.example.OPEN", visible)
        self.assertIn("account [com.example.Account]", visible)
        self.assertIn("opaque object", visible)
        self.assertIn("2 additional extras omitted", visible)

    def test_structured_extras_render_references_errors_and_truncation(self):
        entry = {
            "id": 12, "timestamp": "2026-10-07T08:00:00+00:00",
            "class": "com.example.MainActivity", "method": "getIntent", "stackTrace": [],
            "intent": {
                "extras": {
                    "cycle": {"type": "android.os.Bundle", "value": "reference to #1", "structured": {
                        "kind": "reference", "type": "android.os.Bundle", "referenceId": 1,
                    }},
                    "deep": {"type": "android.os.Bundle", "value": "truncated", "structured": {
                        "kind": "truncated", "type": "android.os.Bundle", "reason": "maximum depth reached",
                    }},
                    "broken": {"type": None, "value": "unreadable", "structured": {
                        "kind": "error", "type": None, "reason": "value could not be read",
                    }},
                },
            },
        }

        visible = plain(render_intent_detail(entry))

        self.assertIn("cycle [Bundle] : reference to #1", visible)
        self.assertIn("deep [Bundle] : maximum depth reached", visible)
        self.assertIn("broken [?] : value could not be read", visible)

    def test_structured_extra_control_characters_do_not_break_tree_rows(self):
        entry = {
            "id": 13, "timestamp": "2026-10-07T08:00:00+00:00",
            "class": "com.example.MainActivity", "method": "getIntent", "stackTrace": [],
            "intent": {"extras": {"text": {
                "type": "java.lang.String", "value": "first\nsecond",
                "structured": {
                    "kind": "scalar", "type": "java.lang.String", "displayType": "String",
                    "noxenType": "string", "value": "first\nsecond",
                },
            }}},
        }

        visible = plain(render_intent_detail(entry))

        self.assertIn('text [String] : "first\\nsecond"', visible)
        self.assertNotIn("first\nsecond", visible)


if __name__ == "__main__":
    unittest.main()
