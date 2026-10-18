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
from noxen.rendering import history_search_matches, render_intent_detail


class CaptureMetadataDBTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = str(Path(directory.name) / "capture.noxen")
        self.db = ProjectDB(self.path)
        self.db.create("capture")
        self.addCleanup(self.db.close)

    def save(self, **metadata):
        info = {"action": "TEST", "extras": {
            str(i): {"type": "java.lang.String", "value": str(i)} for i in range(50)
        }, **metadata}
        entry = {"timestamp": "2026-10-18T08:00:00Z", "class": "Example",
                 "method": "getIntent", "intent": info}
        entry["id"] = self.db.save_intent(entry)
        return entry

    def reopen(self):
        self.db.close()
        return self.db.open_existing()

    def test_omission_count_rendering_search_and_export_survive_reopen(self):
        metadata = {"count": 70, "capturedCount": 50, "omitted": 20,
                    "error": None, "referenceId": 1}
        entry = self.save(extrasMeta=metadata)
        stored = self.reopen()[0]
        self.assertEqual(stored["intent"]["extrasMeta"], metadata)
        self.assertIn("20 additional extras omitted", render_intent_detail(stored))
        self.assertIn("[EXTRAS] (70)", Text.from_markup(render_intent_detail(stored)).plain)
        self.assertTrue(history_search_matches(stored, "omitted"))
        self.assertEqual(history_search_matches(stored, "omitted"), history_search_matches(entry, "omitted"))
        export_path = str(Path(self.path).with_suffix(".json"))
        with patch("noxen.exporting.timestamped_filename", return_value=export_path):
            write_history_export([stored])
        exported = json.loads(Path(export_path).read_text())
        self.assertEqual(exported[0]["intent"]["extrasMeta"], metadata)

    def test_error_without_extras_and_category_markers_survive_reopen(self):
        entry = self.save(extrasMeta={"count": 0, "capturedCount": 0, "omitted": 0,
                                      "error": "Bundle unreadable"},
                          categoriesTruncated=True, categoriesReadError=True)
        entry["intent"]["extras"] = {}
        self.db.update_modified_intent(entry["id"], {}, entry["intent"])
        info = self.reopen()[0]["intent"]
        self.assertEqual(info, {**entry["intent"], "component": None, "data": None,
                                "flags": None, "categories": []})
        self.assertIn("Bundle unreadable", render_intent_detail({**entry, "intent": info}))

    def test_modified_and_original_snapshots_keep_independent_metadata(self):
        original = self.save(extrasMeta={"count": 70, "omitted": 20})
        actual = {**copy.deepcopy(original["intent"]), "action": "CHANGED",
                  "extrasMeta": {"count": 50, "capturedCount": 50, "omitted": 0},
                  "categoriesTruncated": False}
        self.db.update_modified_intent(original["id"], original["intent"], actual)
        stored = self.reopen()[0]
        self.assertEqual(stored["original_intent"], original["intent"])
        self.assertEqual(stored["intent"]["extrasMeta"], actual["extrasMeta"])
        self.assertFalse(stored["intent"]["categoriesTruncated"])
        self.assertNotIn("additional extras omitted", render_intent_detail(stored).split("[CHANGES]")[0])

    def test_metadata_only_update_does_not_create_a_modified_snapshot(self):
        entry = self.save()
        actual = {**entry["intent"], "extrasMeta": {"count": 70, "omitted": 20}}
        self.db.update_capture_metadata(entry["id"], actual)
        stored = self.reopen()[0]
        self.assertEqual(stored["intent"]["extrasMeta"], actual["extrasMeta"])
        self.assertIsNone(stored["original_intent"])
        self.db.update_capture_metadata(entry["id"], entry["intent"])
        self.assertNotIn("extrasMeta", self.reopen()[0]["intent"])

    def test_legacy_migration_is_repeatable_and_does_not_invent_metadata(self):
        self.db.close()
        with sqlite3.connect(self.path) as conn:
            conn.execute("DROP TABLE intents")
            conn.execute("""CREATE TABLE intents (
                id INTEGER PRIMARY KEY, timestamp TEXT, class TEXT, method TEXT,
                action TEXT, component TEXT, data TEXT, flags INTEGER, categories TEXT,
                extras TEXT, stack_trace TEXT, pending_intent_flags INTEGER
            )""")
            conn.execute("INSERT INTO intents (id, timestamp, extras) VALUES (1, 'old', '{}')")
        for _ in range(2):
            stored = self.reopen()[0]
            self.assertEqual(stored["id"], 1)
            self.assertNotIn("extrasMeta", stored["intent"])
            self.assertNotIn("categoriesTruncated", stored["intent"])
            self.assertEqual(self.db.load_warnings, [])

    def test_corrupt_metadata_reports_unavailable_instead_of_complete(self):
        entry = self.save()
        for raw in ("{", "[]", '"text"', "null"):
            with self.subTest(raw=raw):
                with self.db._conn:
                    self.db._conn.execute("UPDATE intents SET capture_metadata=? WHERE id=?",
                                          (raw, entry["id"]))
                stored = self.reopen()[0]
                self.assertTrue(self.db.load_warnings)
                self.assertIn("Capture metadata unavailable", render_intent_detail(stored))

    def test_unknown_metadata_keys_cannot_replace_payload_fields(self):
        entry = self.save()
        with self.db._conn:
            self.db._conn.execute("UPDATE intents SET capture_metadata=? WHERE id=?",
                                  (json.dumps({"action": "WRONG", "extrasMeta": {"omitted": 2}}), entry["id"]))
        stored = self.reopen()[0]
        self.assertEqual(stored["intent"]["action"], "TEST")
        self.assertEqual(stored["intent"]["extrasMeta"], {"omitted": 2})
