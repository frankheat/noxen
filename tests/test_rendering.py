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
    history_search_text,
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
    def test_service_components_keep_metadata_without_routing_in_both_views(self):
        info = {"component": "example/.Work", "selector": {
            "kind": "intent", "component": "example/.Other", "flags": 0,
        }}
        surface = {"serviceComponents": {
            "base": {"component": "example/.Work", "exported": False,
                     "permission": {"name": "example.SERVICE", "level": "signature"}},
            "selector": {"component": "example/.Other", "unavailable": True},
        }, "intentExplicit": True, "selectorRoutingRole": "active", "targetComponent": "wrong/.Target"}
        for method in ("startService", "startForegroundService", "bindService", "getService", "onStartCommand", "onBind"):
            for text in (
                plain(render_intent_detail({"id": 1, "method": method, "intent": info, "attackSurface": surface})),
                plain(render_intercept_block({"methodName": method, "infoIntent": info,
                                               "attackSurface": surface}, 1, False, 1)),
            ):
                base, selector = text.split("[SELECTOR]", 1)
                self.assertIn("Required Permission : example.SERVICE (signature)", base)
                self.assertNotIn("example.SERVICE", selector)
                self.assertIn("Details             : unavailable", selector)
                for value in ("[ROUTING]", "wrong/.Target", "ACTIVE", "Receiver Perm"):
                    self.assertNotIn(value, text)
        info["component"] = None
        text = plain(render_intent_detail({"id": 1, "method": "getService", "intent": info,
                                          "attackSurface": surface, "pendingIntentFlags": 0x04000000}))
        self.assertIn("Component     : None", text)
        self.assertNotIn("example.SERVICE", text)  # no mismatched base metadata
        self.assertIn("[PENDING INTENT]", text)

    def test_broadcast_component_metadata_and_call_permission_are_separate(self):
        surface = {"broadcastComponents": {
            "base": {"component": "example/.Base", "exported": True,
                     "permission": {"name": "example.SEND", "level": "signature"}},
            "selector": {"component": "example/.Selector", "unavailable": True},
        }, "broadcastPermission": {"name": "example.RECEIVE[raw]", "level": "unresolved"},
            "intentExplicit": True, "selectorRoutingRole": "active", "targetComponent": "wrong/.Candidate"}
        info = {"component": "example/.Base", "selector": {"kind": "intent", "component": "example/.Selector"}}
        for method in ("sendBroadcast", "sendOrderedBroadcast", "getBroadcast", "onReceive"):
            for rendered in (
                render_intent_detail({"id": 1, "method": method, "intent": info, "attackSurface": surface}),
                render_intercept_block({"methodName": method, "infoIntent": info, "attackSurface": surface}, 1, False, 1),
            ):
                text = plain(rendered)
                hook, payload = text.split("[CAPTURED INTENT PAYLOAD]", 1)
                self.assertEqual("Receiver Perm" in hook, method in {"sendBroadcast", "sendOrderedBroadcast"})
                self.assertNotIn("Receiver Perm", payload)
                self.assertIn("Required Permission : example.SEND (signature)", payload)
                self.assertIn("Details             : unavailable", payload)
                for forbidden in ("[ROUTING]", "wrong/.Candidate", "ACTIVE", "not visible"):
                    self.assertNotIn(forbidden, text)

    def test_broadcast_permission_null_and_legacy_absence_stay_distinct(self):
        entry = {"id": 1, "method": "sendBroadcast", "intent": {"component": None},
                 "attackSurface": {"broadcastComponents": {}, "broadcastPermission": None}}
        text = plain(render_intent_detail(entry))
        self.assertIn("Receiver Perm : None", text)
        self.assertIn("Component     : None", text)
        entry["attackSurface"]["broadcastPermission"] = {"name": "", "level": "unresolved"}
        self.assertIn('Receiver Perm : "" (empty permission name)', plain(render_intent_detail(entry)))
        del entry["attackSurface"]["broadcastPermission"]
        self.assertNotIn("Receiver Perm", plain(render_intent_detail(entry)))
        entry["attackSurface"] = {"targetComponent": "example/.Candidate", "targetResolved": True,
                                  "targetExported": True, "intentExplicit": False}
        text = plain(render_intent_detail(entry))
        self.assertNotIn("Candidate", text)
        self.assertNotIn("Exported", text)

    def test_activity_component_metadata_stays_with_its_own_object(self):
        info = {"component": "example/.Base", "selector": {
            "kind": "intent", "component": "example/.Selector", "flags": 0,
        }}
        surface = {"activityComponents": {
            "base": {"component": "example/.Base", "exported": True,
                     "permission": {"name": "example.BASE_PERMISSION", "level": "normal"}},
            "selector": {"component": "example/.Selector", "exported": False,
                         "permission": {"name": "example.SELECTOR_PERMISSION", "level": "signature"}},
        }}
        for method in ("startActivity", "startActivityForResult", "getActivity", "getIntent",
                       "onNewIntent", "onActivityResult", "setResult"):
            for rendered in (
                render_intent_detail({"id": 1, "method": method, "intent": info, "attackSurface": surface}),
                render_intercept_block({"methodName": method, "infoIntent": info, "attackSurface": surface}, 1, False, 1),
            ):
                with self.subTest(method=method):
                    text = plain(rendered)
                    base, selector = text.split("[SELECTOR]", 1)
                    self.assertIn("BASE_PERMISSION (normal)", base)
                    self.assertIn("Exported            : true", base)
                    self.assertNotIn("SELECTOR_PERMISSION", base)
                    self.assertIn("SELECTOR_PERMISSION (signature)", selector)
                    self.assertIn("Exported            : false", selector)
                    self.assertNotIn("[ROUTING]", text)

    def test_activity_unavailable_metadata_and_legacy_candidates_are_not_guessed(self):
        entry = {"id": 1, "method": "startActivity", "intent": {"component": "example/.Missing"},
                 "attackSurface": {"activityComponents": {"base": {
                     "component": "example/.Missing", "unavailable": True,
                 }}}}
        text = plain(render_intent_detail(entry))
        self.assertIn("Details             : unavailable", text)
        self.assertNotIn("not visible", text)
        entry["intent"]["component"] = None
        text = plain(render_intent_detail(entry))
        self.assertIn("Component     : None", text)
        self.assertNotIn("unavailable", text)  # mismatched metadata is not reused

        entry["attackSurface"] = {"intentExplicit": False, "targetType": "activity",
                                  "targetComponent": "example/.Candidate", "targetResolved": True,
                                  "targetExported": True}
        text = plain(render_intent_detail(entry))
        self.assertNotIn("Candidate", text)
        self.assertNotIn("Exported", text)

        entry["intent"]["component"] = "example/.Candidate"
        self.assertIn("Exported            : true", plain(render_intent_detail(entry)))
        entry["attackSurface"]["targetUnreadable"] = True
        self.assertIn("Details             : unavailable", plain(render_intent_detail(entry)))

    def test_routing_is_separate_from_objects_in_history_and_intercept(self):
        info = {"component": "example/.Base", "action": "BASE", "selector": {
            "kind": "intent", "component": "example/.Other", "action": "OTHER", "flags": 0,
        }}
        surface = {
            "intentExplicit": True, "routingSource": "base", "selectorRoutingRole": "ignored",
            "targetComponent": "example/.Base", "broadcastPermission": {"name": "example.PERM", "level": "signature"},
        }
        history = render_intent_detail({"id": 1, "intent": info, "attackSurface": surface})
        intercept = render_intercept_block({"infoIntent": info, "attackSurface": surface}, 1, False, 1)
        for rendered in (history, intercept):
            with self.subTest(view=rendered):
                text = plain(rendered)
                self.assertEqual(text.count("[ROUTING]"), 1)
                routing, objects = text.split("[CAPTURED INTENT PAYLOAD]", 1)
                for label in ("Mode", "Source", "Selector", "Target"):
                    self.assertIn(f"  {label:<13} :", routing)
                    self.assertNotIn(f"  {label:<13} :", objects)
                payload, selector = objects.split("[SELECTOR]", 1)
                self.assertIn("Component     : example/.Base", payload)
                self.assertIn("Component     : example/.Other", selector)
                self.assertNotIn("Routing role", text)

    def test_receiving_and_legacy_captures_do_not_invent_routing(self):
        for info in ({}, {"component": "example/.Base", "selector": {"kind": "intent", "flags": 0}}):
            text = plain(render_intent_detail({"id": 1, "method": "onReceive", "intent": info}))
            self.assertNotIn("[ROUTING]", text)
            self.assertNotIn("ACTIVE", text)
            if "component" not in info:
                self.assertNotIn("  Component", text)

    def test_modification_warning_is_visible_in_history_detail_and_row(self):
        entry = {
            "id": 1, "timestamp": "2026-10-14T08:00:00+00:00",
            "class": "Example", "method": "startActivity",
            "intent": {"action": "old", "extras": {}, "categories": []},
            "outcome": "forwarded", "modification_error": "Result [not verified]",
        }
        rendered = plain(render_intent_detail(entry))
        self.assertIn("[MODIFICATION WARNING]", rendered)
        self.assertIn("Result [not verified]", rendered)
        cells = history_row_values(entry, {"outcome"}, [("outcome", "→/✗")])
        self.assertEqual(cells[0].plain, "→ !")

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
                "mimeType": "application/vnd.example.secure+json",
                "flags": 123,
                "categories": ["android.intent.category.DEFAULT"],
                "extras": {"token": {"type": "string", "value": "secret-value"}},
            },
        }

        self.assertTrue(history_search_matches(entry, "mainactivity"))
        self.assertTrue(history_search_matches(entry, "default"))
        self.assertTrue(history_search_matches(entry, "vnd.example.secure"))
        self.assertTrue(history_search_matches(entry, "token"))
        self.assertTrue(history_search_matches(entry, "secret-value"))
        self.assertFalse(history_search_matches(entry, "missing"))

    def test_history_search_matches_nested_structured_values(self):
        entry = {
            "class": "com.example.MainActivity",
            "method": "getIntent",
            "intent": {
                "extras": {
                    "payload": {
                        "type": "android.os.Bundle",
                        "value": "Bundle (2 items)",
                        "structured": {
                            "kind": "bundle",
                            "type": "android.os.Bundle",
                            "omitted": 4,
                            "items": [
                                {
                                    "key": "bundle_tags",
                                    "value": {
                                        "kind": "array",
                                        "type": "[Ljava.lang.String;",
                                        "items": [{
                                            "kind": "scalar",
                                            "type": "java.lang.String",
                                            "value": "deep-value",
                                        }],
                                    },
                                },
                                {
                                    "key": "next",
                                    "value": {
                                        "kind": "intent",
                                        "type": "android.content.Intent",
                                        "action": "com.example.NESTED",
                                        "data": "content://example/item/5",
                                        "mimeType": "application/x-nested-payload",
                                        "component": "com.example/.NestedActivity",
                                        "package": "com.example",
                                        "flags": 16,
                                        "categories": ["com.example.CATEGORY"],
                                        "extras": {
                                            "kind": "bundle",
                                            "items": [
                                                {
                                                    "key": "account",
                                                    "value": {
                                                        "kind": "opaque",
                                                        "type": "com.example.Account",
                                                    },
                                                },
                                                {
                                                    "key": "deeper",
                                                    "value": {
                                                        "kind": "intent",
                                                        "type": "android.content.Intent",
                                                        "action": "com.example.DEEPEST",
                                                    },
                                                },
                                            ],
                                        },
                                    },
                                },
                            ],
                        },
                    },
                    "broken": {
                        "structured": {
                            "kind": "error",
                            "reason": "value could not be read",
                        },
                    },
                },
                "extrasMeta": {"omitted": 2, "error": "some extras were unavailable"},
            },
        }

        for query in (
            "bundle_tags",
            "deep-value",
            "com.example.nested",
            "content://example/item/5",
            "x-nested-payload",
            "nestedactivity",
            "com.example.category",
            "com.example.account",
            "com.example.deepest",
            "opaque",
            "unreadable",
            "could not be read",
            "additional items omitted",
            "additional extras omitted",
            "some extras were unavailable",
        ):
            with self.subTest(query=query):
                self.assertTrue(history_search_matches(entry, query))

    def test_history_search_index_is_bounded_and_tolerates_malformed_nodes(self):
        entry = {
            "class": object(),
            "intent": {
                "categories": "not-a-list",
                "extras": {
                    "malformed": {"structured": {"kind": "bundle", "items": [None, "bad"]}},
                    "large": {"structured": {
                        "kind": "array",
                        "items": [
                            {"kind": "scalar", "value": f"value-{index}-" + ("x" * 3000)}
                            for index in range(500)
                        ],
                    }},
                },
            },
        }

        search_text = history_search_text(entry)

        self.assertLessEqual(len(search_text), 32768)
        self.assertIn("malformed", search_text)
        self.assertIn("value-0", search_text)

    def test_filter_sort_history_entries_uses_prebuilt_search_index(self):
        entry = {
            "id": 1,
            "class": "com.example.MainActivity",
            "method": "getIntent",
            "intent": {"extras": {}},
        }
        filters = FilterManager()
        search_index = {id(entry): "prebuilt\0nested-only"}

        filtered = filter_sort_history_entries(
            [entry],
            filters,
            search_text="nested-only",
            search_index=search_index,
        )

        self.assertEqual(filtered, [entry])

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
                "mimeType": "application/pdf",
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
                "mimeType": "text/plain",
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
        self.assertIn("  MIME Type     : text/plain → application/pdf", plain(rendered))
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
                "mimeType": "application/[bad]",
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
        self.assertNotIn("[ROUTING]", plain(rendered))
        self.assertIn("  Component     : com.example/.Receiver2", plain(rendered))
        self.assertIn("                  ├─ Exported            : true", plain(rendered))
        self.assertIn("                  └─ Required Permission : com.x.PERM (normal)", plain(rendered))
        self.assertIn("  Receiver Perm : com.x.PERM (normal)", plain(rendered))

    def test_render_intent_detail_shows_mime_type_for_new_captures(self):
        entry = {
            "id": 8,
            "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "com.example.MainActivity",
            "method": "startActivity",
            "intent": {"action": "android.intent.action.VIEW", "mimeType": "image/*"},
            "attackSurface": {"intentExplicit": False, "targetType": "activity"},
            "stackTrace": [],
        }

        self.assertIn("  MIME Type     : image/*", plain(render_intent_detail(entry)))

        entry["intent"]["mimeType"] = None
        self.assertIn("  MIME Type     : None", plain(render_intent_detail(entry)))

        del entry["intent"]["mimeType"]
        self.assertNotIn("MIME Type", plain(render_intent_detail(entry)))

    def test_legacy_service_candidates_are_not_presented_as_actual_components(self):
        base = {
            "id": 1, "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "com.example.MainActivity", "method": "startService", "stackTrace": [],
            "intent": {},
        }
        unresolved = dict(base, attackSurface={"intentExplicit": False})
        self.assertNotIn("  Target", plain(render_intent_detail(unresolved)))

        unreadable = dict(base, attackSurface={
            "intentExplicit": True, "targetComponent": "com.other/.X", "targetUnreadable": True,
        })
        self.assertNotIn("com.other/.X", plain(render_intent_detail(unreadable)))

        resolved_single = dict(base, attackSurface={
            "intentExplicit": False, "targetComponent": "com.example/.Activity8",
            "targetResolved": True, "targetExported": True,
        })
        self.assertNotIn("com.example/.Activity8", plain(render_intent_detail(resolved_single)))
        resolved_single["intent"] = {"component": "com.example/.Activity8"}
        text = plain(render_intent_detail(resolved_single))
        self.assertIn("Component     : com.example/.Activity8", text)
        self.assertIn("Exported            : true", text)
        self.assertNotIn("[ROUTING]", text)

    def test_implicit_intent_scope_and_package_row(self):
        base = {
            "id": 1, "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "com.example.MainActivity", "method": "sendBroadcast", "stackTrace": [],
            "attackSurface": {"intentExplicit": False, "targetType": "receiver"},
        }
        open_to_all = dict(base, intent={"action": "com.example.PING", "package": None})
        scoped = dict(base, intent={"action": "com.example.PING", "package": "com.example"})
        legacy = dict(base, intent={"action": "com.example.PING"})  # captured before the package was recorded

        self.assertNotIn("[ROUTING]", plain(render_intent_detail(open_to_all)))
        self.assertNotIn("Package", plain(render_intent_detail(open_to_all)))
        self.assertNotIn("[ROUTING]", plain(render_intent_detail(scoped)))
        self.assertIn("  Package       : com.example", plain(render_intent_detail(scoped)))
        legacy_text = plain(render_intent_detail(legacy))
        self.assertNotIn("[ROUTING]", legacy_text)
        self.assertNotIn("  Source", legacy_text)

    def test_activity_shows_component_instead_of_routing_classification(self):
        entry = {
            "id": 1, "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "com.example.MainActivity", "method": "startActivity", "stackTrace": [],
            "intent": {"component": "com.example/.A", "package": None},
            "attackSurface": {"intentExplicit": True, "targetComponent": "com.example/.A", "targetType": "activity"},
        }
        text = plain(render_intent_detail(entry))
        self.assertIn("  Component     : com.example/.A", text)
        self.assertNotIn("[ROUTING]", text)
        self.assertNotIn("  Target", text)

    def test_activity_selector_fields_do_not_imply_routing(self):
        selector = {
            "kind": "intent", "type": "android.content.Intent", "displayType": "Intent",
            "component": "com.example/.SelectorActivity", "action": "com.example.SELECT",
            "data": "content://selector/1", "mimeType": "application/selector",
            "package": None, "flags": 0, "categories": [], "extras": None,
        }
        entry = {
            "id": 1, "timestamp": "2026-10-10T08:00:00+00:00",
            "class": "com.example.MainActivity", "method": "startActivity", "stackTrace": [],
            "intent": {
                "component": None, "action": "com.example.BASE", "package": None,
                "selector": selector,
            },
            "attackSurface": {
                "intentExplicit": True, "routingSource": "selector",
                "selectorRoutingRole": "active", "routingPackage": None,
                "targetComponent": "com.example/.SelectorActivity", "targetType": "activity",
            },
        }

        visible = plain(render_intent_detail(entry))

        self.assertNotIn("[ROUTING]", visible)
        self.assertNotIn("  Target", visible)
        self.assertNotIn("SelectorActivity (resolved)", visible)
        self.assertIn("[SELECTOR]", visible)
        payload = visible.split("[CAPTURED INTENT PAYLOAD]", 1)[1]
        self.assertNotIn("  Mode", payload)
        self.assertNotIn("  Selector      :", payload)
        self.assertNotIn("  Component", payload.split("[SELECTOR]")[0])
        self.assertIn("  Action        : com.example.SELECT", visible)
        self.assertIn("  MIME Type     : application/selector", visible)

        selector["component"] = None
        selector["package"] = "com.example"
        entry["attackSurface"].update({
            "intentExplicit": False,
            "routingPackage": "com.example",
            "targetComponent": None,
        })
        self.assertNotIn("[ROUTING]", plain(render_intent_detail(entry)))
        self.assertIn("  Package       : com.example", plain(render_intent_detail(entry)))

        selector["package"] = None
        entry["attackSurface"]["routingPackage"] = None
        self.assertNotIn("[ROUTING]", plain(render_intent_detail(entry)))

    def test_activity_keeps_different_base_and_selector_components_without_roles(self):
        selector = {
            "kind": "intent", "type": "android.content.Intent", "displayType": "Intent",
            "component": "com.example/.ActivityB", "action": None, "data": None,
            "mimeType": None, "package": None, "flags": 0, "categories": [], "extras": None,
        }
        entry = {
            "id": 2, "timestamp": "2026-10-10T08:00:00+00:00",
            "class": "com.example.MainActivity", "method": "startActivity", "stackTrace": [],
            "intent": {"component": "com.example/.ActivityA", "selector": selector},
            "attackSurface": {
                "intentExplicit": True, "routingSource": "base",
                "selectorRoutingRole": "ignored", "routingPackage": None,
                "targetComponent": "com.example/.ActivityA", "targetType": "activity",
            },
        }

        visible = plain(render_intent_detail(entry))

        self.assertNotIn("[ROUTING]", visible)
        self.assertIn("  Component     : com.example/.ActivityA", visible)
        self.assertIn("  Component     : com.example/.ActivityB", visible)

        entry["attackSurface"]["selectorRoutingRole"] = "redundant"
        self.assertNotIn("REDUNDANT", plain(render_intent_detail(entry)))

    def test_history_search_includes_recursive_selector_fields(self):
        entry = {
            "intent": {
                "selector": {
                    "kind": "intent", "type": "android.content.Intent", "displayType": "Intent",
                    "action": "com.example.SELECT", "component": "com.example/.SelectorActivity",
                    "data": None, "mimeType": None, "package": None, "flags": 0,
                    "categories": [], "extras": None,
                    "selector": {
                        "kind": "intent", "type": "android.content.Intent", "displayType": "Intent",
                        "action": "com.example.NESTED", "component": None, "data": None,
                        "mimeType": "application/nested-selector", "package": None,
                        "flags": 0, "categories": [], "extras": None,
                    },
                },
            },
        }

        self.assertTrue(history_search_matches(entry, "selectoractivity"))
        self.assertTrue(history_search_matches(entry, "com.example.nested"))
        self.assertTrue(history_search_matches(entry, "application/nested-selector"))

    def test_clip_data_renders_and_searches_nested_intent(self):
        clip = {
            "kind": "clipdata", "type": "android.content.ClipData", "displayType": "ClipData",
            "label": "documents", "mimeTypes": ["text/html"], "count": 2,
            "items": [
                {"kind": "clipitem", "displayType": "Item", "uri": "content://example/private/report"},
                {"kind": "clipitem", "displayType": "Item", "text": "hello [world]",
                 "html": "<b>hello</b>",
                 "intent": {"kind": "intent", "displayType": "Intent", "action": "example.NESTED",
                            "flags": 2,
                            "clipData": {"kind": "clipdata", "displayType": "ClipData",
                                         "label": "inner clip", "mimeTypes": ["text/plain"],
                                         "count": 1, "items": [{"kind": "clipitem", "text": "inner text"}]}}},
            ],
        }
        entry = {"id": 1, "timestamp": "2026-10-13T08:00:00+00:00", "class": "Main",
                 "method": "startActivity", "intent": {"flags": 1, "clipData": clip}}
        detail = plain(render_intent_detail(entry))
        self.assertIn("[CLIP DATA] (2 items)", detail)
        self.assertNotIn("└─ [ClipData]", detail)
        self.assertIn("  Label         : documents", detail)
        self.assertIn("  MIME Type     : text/html", detail)
        self.assertIn("  ├─ Item 0 [Item]", detail)
        self.assertIn("Grant flags   : READ (outer Intent)", detail)
        self.assertIn("Grant flags   : READ (outer Intent)", plain(render_intercept_block(
            {"className": "Main", "methodName": "startActivity", "infoIntent": entry["intent"]},
            1, False, 10,
        )))
        for value in ("documents", "text/html", "content://example/private/report",
                      "hello [world]", "example.NESTED", "inner clip", "inner text"):
            self.assertIn(value, detail)
            self.assertTrue(history_search_matches(entry, value))
        self.assertIn("FLAG_GRANT_READ_URI_PERMISSION", detail)
        for flags, expected in ((0, "none"), (0xC3, "READ | WRITE | PERSISTABLE | PREFIX"),
                                ("invalid", "unavailable")):
            updated = {**entry, "intent": {**entry["intent"], "flags": flags}}
            self.assertIn(f"Grant flags   : {expected} (outer Intent)", plain(render_intent_detail(updated)))
        self.assertNotIn("[CLIP DATA]", plain(render_intent_detail({**entry, "intent": {}})))

    def test_clip_data_grant_flags_only_appear_with_captured_uri(self):
        inner = {"kind": "clipdata", "count": 1, "items": [
            {"kind": "clipitem", "text": "inner text"},
        ]}
        nested = {"kind": "intent", "data": None, "flags": 2, "clipData": inner}
        clip = {"kind": "clipdata", "count": 1, "items": [
            {"kind": "clipitem", "text": "visible text", "intent": nested},
        ]}
        entry = {"id": 1, "timestamp": "2026-10-13T08:00:00+00:00", "class": "Main",
                 "method": "startActivity", "intent": {"flags": 1, "clipData": clip}}

        self.assertIn("[CLIP DATA]", plain(render_intent_detail(entry)))
        self.assertNotIn("Grant flags", plain(render_intent_detail(entry)))
        self.assertNotIn("Grant flags", plain(render_intercept_block(
            {"className": "Main", "methodName": "startActivity", "infoIntent": entry["intent"]},
            1, False, 10,
        )))

        inner["items"][0]["uri"] = "content://example/nested"
        self.assertIn("Grant flags   : READ (outer Intent)", plain(render_intent_detail(entry)))
        del inner["items"][0]["uri"]
        nested["data"] = "content://example/intent-data"
        self.assertIn("Grant flags   : READ (outer Intent)", plain(render_intent_detail(entry)))

    def test_broadcast_without_manifest_receiver_is_not_called_unresolved(self):
        base = {
            "id": 1, "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "com.example.MainActivity", "stackTrace": [], "intent": {"package": None},
        }
        broadcast = dict(base, method="sendBroadcast",
                         attackSurface={"intentExplicit": False, "targetType": "receiver"})
        text = plain(render_intent_detail(broadcast))
        self.assertNotIn("  Target", text)
        self.assertNotIn("(unresolved)", text)
        # Activities no longer query or display an implicit candidate.
        activity = dict(base, method="startActivity",
                        attackSurface={"intentExplicit": False, "targetType": "activity"})
        self.assertNotIn("  Target", plain(render_intent_detail(activity)))

    def test_detail_grey_scale_dims_labels_not_values(self):
        entry = {
            "id": 3, "timestamp": "2026-04-27T12:34:56+00:00",
            "class": "com.example.MainActivity", "method": "sendBroadcast", "stackTrace": [],
            "intent": {"component": "com.example/.R", "action": "a.B", "extras": {"k": {"type": "java.lang.String", "value": "v"}}},
            "attackSurface": {"intentExplicit": True, "targetComponent": "com.example/.R",
                              "targetExported": True, "targetResolved": True},
        }
        rendered = render_intent_detail(entry)
        self.assertIn("  [dim]Action        :[/dim] a.B", rendered)
        self.assertIn("[dim]└─ Exported            :[/dim] true", rendered)
        self.assertNotIn("(resolved)", rendered)
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
                                    "data": None, "mimeType": "text/plain", "flags": 1, "categories": [],
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
        self.assertIn("MIME Type     : text/plain", visible)
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
