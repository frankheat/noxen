import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rich.text import Text

from noxen.db import ProjectDB
from noxen.exporting import write_history_export
from noxen.filters import FilterManager
from noxen.rendering import (
    entry_to_filter_context,
    history_search_matches,
    history_search_text,
    render_intent_detail,
)


class IntentFlagsDBTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = str(Path(directory.name) / "flags.noxen")
        self.db = ProjectDB(self.path)
        self.db.create("flags")
        self.addCleanup(self.db.close)

    def entry(self, flags):
        return {
            "timestamp": "2026-10-18T08:00:00Z",
            "class": "Example", "method": "getIntent",
            "intent": {
                "action": "TEST", "component": None, "data": None,
                "mimeType": None, "flags": flags, "categories": [], "extras": {},
            },
        }

    def reopen(self):
        self.db.close()
        return self.db.open_existing()

    def test_captured_flag_masks_survive_save_and_repeated_reopen(self):
        masks = [None, 0, 1, 0xC3, 0x80000000, 0xFFFFFFFF, -0x80000000, -1]
        for flags in masks:
            entry = self.entry(flags)
            entry["pendingIntentFlags"] = 0
            self.db.save_intent(entry)
        for _ in range(2):
            rows = self.reopen()
            self.assertEqual([e["intent"]["flags"] for e in rows], masks)
            self.assertEqual([e["pendingIntentFlags"] for e in rows], [0] * len(masks))
            self.assertEqual(self.db.load_warnings, [])
            with sqlite3.connect(self.path) as conn:
                self.assertEqual([r[0] for r in conn.execute("SELECT flags FROM intents ORDER BY id")], masks)

    def test_modified_masks_and_original_snapshots_survive_reopen(self):
        pairs = [(1, 0), (0, 1), (0, 0), (None, 0), (0, None), (0xFFFFFFFF, 0), (0, -1)]
        for before, after in pairs:
            entry = self.entry(before)
            row_id = self.db.save_intent(entry)
            modified = copy.deepcopy(entry["intent"])
            modified["flags"] = after
            self.db.update_modified_intent(row_id, entry["intent"], modified)
            self.db.update_outcome(row_id, "modified_forwarded")
        for _ in range(2):
            rows = self.reopen()
            self.assertEqual([e["intent"]["flags"] for e in rows], [p[1] for p in pairs])
            self.assertEqual([e["original_intent"]["flags"] for e in rows], [p[0] for p in pairs])
            self.assertTrue(all(e["outcome"] == "modified_forwarded" for e in rows))
            with sqlite3.connect(self.path) as conn:
                self.assertEqual([r[0] for r in conn.execute("SELECT flags FROM intents ORDER BY id")],
                                 [p[1] for p in pairs])

    def test_search_rendering_filtering_and_json_export_are_stable(self):
        entries = [self.entry(flags) for flags in (0, 1, 0xC3, None)]
        for entry in entries:
            entry["id"] = self.db.save_intent(entry)
        self.assertTrue(history_search_matches(entries[0], "0"))
        rules = FilterManager()
        rules.add("focus", ["flags=0"])
        stored = self.reopen()
        for original, loaded in zip(entries, stored):
            with self.subTest(flags=original["intent"]["flags"]):
                self.assertEqual(history_search_text(loaded), history_search_text(original))
                self.assertEqual(render_intent_detail(loaded), render_intent_detail(original))
                self.assertEqual(entry_to_filter_context(loaded), entry_to_filter_context(original))
                self.assertEqual(rules.is_visible(entry_to_filter_context(loaded)),
                                 rules.is_visible(entry_to_filter_context(original)))
        export_path = str(Path(self.path).with_suffix(".json"))
        with patch("noxen.exporting.timestamped_filename", return_value=export_path):
            write_history_export(stored)
        exported = json.loads(Path(export_path).read_text())
        self.assertEqual([e["intent"]["flags"] for e in exported], [0, 1, 0xC3, None])

    def test_clipdata_grant_summary_keeps_none_distinct_from_unavailable(self):
        for flags, expected in ((0, "none"), (None, "unavailable"), (1, "READ")):
            with self.subTest(flags=flags):
                entry = self.entry(flags)
                entry["intent"]["clipData"] = {
                    "kind": "clipdata", "count": 1, "mimeTypes": ["text/uri-list"],
                    "items": [{"kind": "clipitem", "uri": "content://example/item"}],
                }
                row_id = self.db.save_intent(entry)
                entry["id"] = row_id
                stored = next(e for e in self.reopen() if e["id"] == row_id)
                before = Text.from_markup(render_intent_detail(entry)).plain
                after = Text.from_markup(render_intent_detail(stored)).plain
                self.assertIn(f"Grant flags   : {expected} (outer Intent)", after)
                self.assertEqual(after, before)

    def test_missing_flags_and_null_intent_are_not_assigned_zero(self):
        for surface in ({}, {"intentPresent": False}):
            entry = self.entry(None)
            del entry["intent"]["flags"]
            entry["attackSurface"] = surface
            self.db.save_intent(entry)
        for row in self.reopen():
            self.assertIsNone(row["intent"]["flags"])

    def test_legacy_sql_values_are_not_reinterpreted_during_migration(self):
        self.db.close()
        with sqlite3.connect(self.path) as conn:
            conn.execute("DROP TABLE intents")
            conn.execute("""CREATE TABLE intents (
                id INTEGER PRIMARY KEY, timestamp TEXT, class TEXT, method TEXT,
                action TEXT, component TEXT, data TEXT, flags INTEGER, categories TEXT,
                extras TEXT, stack_trace TEXT, pending_intent_flags INTEGER
            )""")
            conn.executemany("INSERT INTO intents (id, timestamp, flags) VALUES (?, 'old', ?)",
                             [(1, None), (2, 0), (3, 17), (4, -1)])
        for _ in range(2):
            rows = self.reopen()
            self.assertEqual([e["intent"]["flags"] for e in rows], [None, 0, 17, -1])
            self.assertEqual(self.db.load_warnings, [])
            with sqlite3.connect(self.path) as conn:
                self.assertEqual(conn.execute("SELECT id, flags FROM intents ORDER BY id").fetchall(),
                                 [(1, None), (2, 0), (3, 17), (4, -1)])


if __name__ == "__main__":
    unittest.main()
