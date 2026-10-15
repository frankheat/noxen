import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from noxen.db import ProjectDB
from noxen.filters import FilterManager
from noxen.history_columns import parse_history_column_width
from noxen.rendering import render_intent_detail
from noxen.settings import load_settings, save_settings, settings_file_path


class FilterManagerTests(unittest.TestCase):
    def test_from_saved_preserves_next_id(self):
        manager = FilterManager.from_saved([
            {"id": 4, "type": "focus", "rule": {"method": "sendBroadcast"}, "enabled": True}
        ])

        msg = manager.add("ignore", ["class=com.example.*"])

        self.assertIn("filter #5", msg)
        self.assertEqual(
            manager.export(),
            [
                {"id": 4, "type": "focus", "rule": {"method": "sendBroadcast"}, "enabled": True},
                {"id": 5, "type": "ignore", "rule": {"class": "com.example.*"}, "enabled": True},
            ],
        )

    def test_export_returns_copy(self):
        manager = FilterManager()
        manager.add("ignore", ["method=startActivity"])

        exported = manager.export()
        exported.clear()

        ignore, focus = manager.get_active()
        self.assertEqual(ignore, [{"method": "startActivity"}])
        self.assertEqual(focus, [])

    def test_from_saved_discards_invalid_filters(self):
        manager = FilterManager.from_saved([
            {"id": 2, "type": "ignore", "rule": {"method": "getIntent"}, "enabled": True},
            {"id": "bad", "type": "ignore", "rule": {"method": "startActivity"}, "enabled": True},
            {"id": 3, "type": "unknown", "rule": {"method": "sendBroadcast"}, "enabled": True},
            {"id": 4, "type": "focus", "rule": {"bad": "key"}, "enabled": True},
            {"id": 5, "type": "focus", "rule": {"flags": 1}, "enabled": True},
            "not-a-filter",
        ])

        self.assertEqual(
            manager.export(),
            [{"id": 2, "type": "ignore", "rule": {"method": "getIntent"}, "enabled": True}],
        )

        msg = manager.add("focus", ["action=android.intent.action.VIEW"])
        self.assertIn("filter #3", msg)

    def test_get_active_returns_copies(self):
        manager = FilterManager()
        manager.add("ignore", ["method=startActivity"])

        ignore, _focus = manager.get_active()
        ignore[0]["method"] = "changed"

        ignore_again, _focus_again = manager.get_active()
        self.assertEqual(ignore_again, [{"method": "startActivity"}])

    def test_add_rejects_invalid_filter_type(self):
        manager = FilterManager()

        msg = manager.add("bad", ["method=startActivity"])

        self.assertIn("Unknown filter type", msg)
        self.assertEqual(manager.export(), [])

    def test_is_visible_uses_ignore_filters_when_no_focus_filter_exists(self):
        manager = FilterManager()
        manager.add("ignore", ["method=getIntent"])

        self.assertFalse(manager.is_visible({"method": "getIntent"}))
        self.assertTrue(manager.is_visible({"method": "sendBroadcast"}))

    def test_is_visible_focus_filters_take_precedence_over_ignore_filters(self):
        manager = FilterManager()
        manager.add("ignore", ["method=getIntent"])
        manager.add("focus", ["action=android.intent.action.VIEW"])

        self.assertTrue(manager.is_visible({
            "method": "getIntent",
            "action": "android.intent.action.VIEW",
        }))
        self.assertFalse(manager.is_visible({
            "method": "sendBroadcast",
            "action": "android.intent.action.SEND",
        }))


class SettingsTests(unittest.TestCase):
    def test_settings_file_uses_xdg_config_home_on_linux(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("sys.platform", "linux"):
                with patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp}, clear=False):
                    self.assertEqual(settings_file_path(), Path(tmp) / "noxen" / "settings.txt")

    def test_settings_file_uses_application_support_on_macos(self):
        with patch("sys.platform", "darwin"):
            self.assertEqual(
                settings_file_path(),
                Path.home() / "Library" / "Application Support" / "noxen" / "settings.txt",
            )

    def test_settings_file_uses_appdata_on_windows(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("sys.platform", "win32"):
                with patch.dict(os.environ, {"APPDATA": tmp}, clear=False):
                    self.assertEqual(settings_file_path(), Path(tmp) / "noxen" / "settings.txt")

    def test_load_settings_uses_defaults_for_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "settings.txt")
            self.assertEqual(
                load_settings(path),
                {
                    "stack": False,
                    "stack_depth": 15,
                    "intercept": True,
                    "intercept_command_bar": True,
                    "history_command_bar": True,
                },
            )

    def test_save_and_load_settings_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config", "settings.txt")
            save_settings({
                "stack": True,
                "stack_depth": 7,
                "intercept": False,
                "intercept_command_bar": False,
                "history_command_bar": True,
            }, path)
            self.assertEqual(
                load_settings(path),
                {
                    "stack": True,
                    "stack_depth": 7,
                    "intercept": False,
                    "intercept_command_bar": False,
                    "history_command_bar": True,
                },
            )

    def test_load_settings_ignores_invalid_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "settings.txt")
            with open(path, "w") as f:
                f.write("stack=maybe\n")
                f.write("stack_depth=0\n")
                f.write("intercept=disabled\n")
                f.write("intercept_command_bar=hidden\n")
                f.write("history_command_bar=visible\n")

            self.assertEqual(
                load_settings(path),
                {
                    "stack": False,
                    "stack_depth": 15,
                    "intercept": True,
                    "intercept_command_bar": True,
                    "history_command_bar": True,
                },
            )

    def test_load_settings_accepts_valid_off_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "settings.txt")
            with open(path, "w") as f:
                f.write("stack=off\n")
                f.write("stack_depth=3\n")
                f.write("intercept=off\n")
                f.write("intercept_command_bar=off\n")
                f.write("history_command_bar=off\n")

            self.assertEqual(
                load_settings(path),
                {
                    "stack": False,
                    "stack_depth": 3,
                    "intercept": False,
                    "intercept_command_bar": False,
                    "history_command_bar": False,
                },
            )


class HistoryColumnWidthTests(unittest.TestCase):
    def test_parse_history_column_width_accepts_auto_and_empty_values(self):
        self.assertEqual(parse_history_column_width("auto"), (None, ""))
        self.assertEqual(parse_history_column_width(""), (None, ""))

    def test_parse_history_column_width_rejects_non_numeric_values_with_auto_hint(self):
        self.assertEqual(
            parse_history_column_width("wide"),
            (None, "Width must be a number or auto"),
        )

    def test_parse_history_column_width_validates_range(self):
        self.assertEqual(parse_history_column_width("5"), (5, ""))
        self.assertEqual(parse_history_column_width("150"), (150, ""))
        self.assertEqual(
            parse_history_column_width("4"),
            (None, "Width must be auto or between 5 and 150"),
        )


class ProjectDBTests(unittest.TestCase):
    def test_open_existing_migrates_legacy_intents_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "legacy.noxen")
            conn = sqlite3.connect(path)
            conn.executescript("""
                CREATE TABLE project_info (
                    key   TEXT PRIMARY KEY,
                    value TEXT
                );
                CREATE TABLE intents (
                    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp            TEXT    NOT NULL,
                    class                TEXT,
                    method               TEXT,
                    action               TEXT,
                    component            TEXT,
                    data                 TEXT,
                    flags                TEXT,
                    categories           TEXT,
                    extras               TEXT,
                    stack_trace          TEXT,
                    pending_intent_flags INTEGER
                );
            """)
            conn.commit()
            conn.close()

            db = ProjectDB(path)
            db.open_existing()
            db.close()

            conn = sqlite3.connect(path)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(intents)")}
            conn.close()

            self.assertIn("outcome", columns)
            self.assertIn("original_intent", columns)
            self.assertIn("mime_type", columns)
            self.assertIn("selector", columns)
            self.assertIn("clip_data", columns)
            self.assertIn("intent_package", columns)

    def test_package_roundtrip_preserves_value_null_empty_and_uncaptured(self):
        infos = [{"package": "dev.example"}, {"package": None}, {"package": ""}, {}]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "project.noxen")
            db = ProjectDB(path)
            db.create("project")
            for info in infos:
                db.save_intent({"timestamp": "2026-10-15T08:00:00+00:00", "intent": info})
            db.close()

            for _ in range(2):
                reopened = ProjectDB(path)
                entries = reopened.open_existing()
                reopened.close()
                for info, entry in zip(infos, entries):
                    with self.subTest(info=info):
                        if "package" in info:
                            self.assertIn("package", entry["intent"])
                            self.assertEqual(entry["intent"]["package"], info["package"])
                        else:
                            self.assertNotIn("package", entry["intent"])

    def test_package_and_routing_render_identically_after_reopen(self):
        selector = {"kind": "intent", "package": "dev.selector", "action": "SELECT"}
        scenarios = [
            ({"package": "dev.example"}, {"intentExplicit": False}),
            ({"package": None}, {"intentExplicit": False}),
            ({}, {"intentExplicit": False}),
            ({"package": "dev.example"}, {
                "intentExplicit": False, "routingSource": "base", "routingPackage": "dev.example",
            }),
            ({"package": None, "selector": selector}, {
                "intentExplicit": False, "routingSource": "selector", "routingPackage": "dev.selector",
            }),
            ({"package": "dev.example", "component": "dev.example/.Target"}, {
                "intentExplicit": True, "routingSource": "base", "routingPackage": "dev.example",
            }),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "project.noxen")
            db = ProjectDB(path)
            db.create("project")
            expected = []
            for info, surface in scenarios:
                entry = {
                    "timestamp": "2026-10-15T08:00:00+00:00", "class": "dev.example.Main",
                    "method": "sendBroadcast", "intent": info, "attackSurface": surface,
                }
                entry["id"] = db.save_intent(entry)
                expected.append(render_intent_detail(entry))
            db.close()
            reopened = ProjectDB(path)
            entries = reopened.open_existing()
            reopened.close()
            self.assertEqual([render_intent_detail(entry) for entry in entries], expected)

    def test_modified_intent_preserves_package_and_original_snapshot(self):
        for before, after in (("dev.example", "dev.example"), (None, None), ("", ""),
                              ("dev.old", "dev.new"), ("dev.example", None)):
            with self.subTest(before=before, after=after), tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "project.noxen")
                db = ProjectDB(path)
                db.create("project")
                original = {"package": before, "action": "OLD", "extras": {}}
                final = {**original, "package": after, "action": "NEW"}
                row_id = db.save_intent({"timestamp": "2026-10-15T08:00:00+00:00", "intent": original})
                db.update_modified_intent(row_id, original, final)
                db.update_outcome(row_id, "modified_forwarded")
                db.close()
                reopened = ProjectDB(path)
                entry = reopened.open_existing()[0]
                reopened.close()
                self.assertEqual(entry["intent"]["package"], after)
                self.assertEqual(entry["intent"]["action"], "NEW")
                self.assertEqual(entry["original_intent"], original)
                self.assertEqual(entry["outcome"], "modified_forwarded")

    def test_package_migration_does_not_infer_outer_package_from_routing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "legacy.noxen")
            db = ProjectDB(path)
            db.create("legacy")
            row_id = db.save_intent({
                "timestamp": "2026-10-15T08:00:00+00:00", "intent": {"action": "OLD"},
                "attackSurface": {"routingSource": "selector", "routingPackage": "dev.selector"},
            })
            db.close()
            with sqlite3.connect(path) as conn:
                columns = {row[1] for row in conn.execute("PRAGMA table_info(intents)")}
                if "intent_package" in columns:
                    conn.execute("ALTER TABLE intents DROP COLUMN intent_package")
            for _ in range(2):
                reopened = ProjectDB(path)
                entry = reopened.open_existing()[0]
                reopened.close()
                self.assertNotIn("package", entry["intent"])
                self.assertEqual(entry["id"], row_id)
                self.assertEqual(entry["intent"]["action"], "OLD")
                self.assertEqual(entry["attackSurface"]["routingPackage"], "dev.selector")

    def test_mime_type_roundtrip_distinguishes_absent_null_and_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "project.noxen")
            db = ProjectDB(path)
            db.create("project")
            for mime_type in ("image/*", None):
                db.save_intent({
                    "timestamp": "2026-10-10T08:00:00+00:00",
                    "intent": {"mimeType": mime_type},
                })
            db.save_intent({
                "timestamp": "2026-10-10T08:00:00+00:00",
                "intent": {},
            })
            db.close()

            reopened = ProjectDB(path)
            entries = reopened.open_existing()
            reopened.close()

            self.assertEqual(entries[0]["intent"]["mimeType"], "image/*")
            self.assertIsNone(entries[1]["intent"]["mimeType"])
            self.assertNotIn("mimeType", entries[2]["intent"])

    def test_selector_roundtrip_distinguishes_legacy_absent_null_and_tree(self):
        selector = {
            "kind": "intent", "type": "android.content.Intent", "displayType": "Intent",
            "component": "com.example/.Target", "action": "com.example.SELECT",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "project.noxen")
            db = ProjectDB(path)
            db.create("project")
            db.save_intent({"timestamp": "2026-10-10T08:00:00+00:00", "intent": {"selector": selector}})
            db.save_intent({"timestamp": "2026-10-10T08:00:00+00:00", "intent": {"selector": None}})
            db.save_intent({"timestamp": "2026-10-10T08:00:00+00:00", "intent": {}})
            db.close()

            reopened = ProjectDB(path)
            entries = reopened.open_existing()
            reopened.close()

            self.assertEqual(entries[0]["intent"]["selector"], selector)
            self.assertIsNone(entries[1]["intent"]["selector"])
            self.assertNotIn("selector", entries[2]["intent"])

    def test_clip_data_roundtrip_distinguishes_legacy_absent_null_and_tree(self):
        clip = {"kind": "clipdata", "label": "documents", "count": 1,
                "items": [{"kind": "clipitem", "uri": "content://example/document"}]}
        with tempfile.TemporaryDirectory() as tmp:
            db = ProjectDB(os.path.join(tmp, "project.noxen"))
            db.create("project")
            for info in ({"clipData": clip}, {"clipData": None}, {}):
                db.save_intent({"timestamp": "2026-10-13T08:00:00+00:00", "intent": info})
            db.close()

            reopened = ProjectDB(os.path.join(tmp, "project.noxen"))
            entries = reopened.open_existing()
            reopened.close()

            self.assertEqual(entries[0]["intent"]["clipData"], clip)
            self.assertIsNone(entries[1]["intent"]["clipData"])
            self.assertNotIn("clipData", entries[2]["intent"])

    def test_filter_lists_roundtrip_through_project_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "project.noxen")
            db = ProjectDB(path)
            db.create("project")
            filters = [
                {"id": 1, "type": "ignore", "rule": {"method": "getIntent"}, "enabled": True}
            ]
            db.save_intercept_filters(filters)
            db.save_history_filters(filters)
            db.close()

            reopened = ProjectDB(path)
            reopened.open_existing()
            self.assertEqual(reopened.load_intercept_filters(), filters)
            self.assertEqual(reopened.load_history_filters(), filters)
            reopened.close()

    def test_session_file_paths_roundtrip_through_project_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "project.noxen")
            db = ProjectDB(path)
            db.create("project")
            db.save_hook_config_path("/tmp/hooks.json")
            db.save_extra_script_path("/tmp/extra.js")
            db.close()

            reopened = ProjectDB(path)
            reopened.open_existing()
            self.assertEqual(reopened.load_hook_config_path(), "/tmp/hooks.json")
            self.assertEqual(reopened.load_extra_script_path(), "/tmp/extra.js")

            reopened.save_hook_config_path("")
            reopened.save_extra_script_path("")
            reopened.close()

            cleared = ProjectDB(path)
            cleared.open_existing()
            self.assertEqual(cleared.load_hook_config_path(), "")
            self.assertEqual(cleared.load_extra_script_path(), "")
            cleared.close()

    def test_history_column_widths_roundtrip_through_project_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "project.noxen")
            db = ProjectDB(path)
            db.create("project")
            db.save_history_column_widths({
                "time": 19,
                "method": 12,
                "class": "40",
                "component": 150,
                "action": 4,
                "unknown": 20,
            })
            db.close()

            reopened = ProjectDB(path)
            reopened.open_existing()
            self.assertEqual(
                reopened.load_history_column_widths(),
                {"time": 19, "method": 12, "class": 40, "component": 150},
            )
            reopened.close()

    def test_invalid_project_info_json_falls_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "project.noxen")
            db = ProjectDB(path)
            db.create("project")
            db.set_info("intercept_filters", "{not-json")
            db.set_info("history_filters", '{"bad": "shape"}')
            db.set_info("history_columns", '{"bad": "shape"}')
            db.set_info("history_column_widths", '["bad"]')

            self.assertEqual(db.load_intercept_filters(), [])
            self.assertEqual(db.load_history_filters(), [])
            self.assertIsNone(db.load_history_columns())
            self.assertEqual(db.load_history_column_widths(), {})
            db.close()

    def test_invalid_intent_json_uses_safe_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "project.noxen")
            db = ProjectDB(path)
            db.create("project")
            db.save_intent({
                "timestamp": "2026-04-29T10:00:00+00:00",
                "intent": {
                    "categories": ["android.intent.category.DEFAULT"],
                    "extras": {"token": "value"},
                    "flags": 1,
                },
                "stackTrace": ["frame"],
            })
            db.close()

            conn = sqlite3.connect(path)
            conn.execute(
                """UPDATE intents SET
                   categories=?, extras=?, stack_trace=?, original_intent=?
                   WHERE id=1""",
                ("{bad-json", "{bad-json", "{bad-json", "{bad-json"),
            )
            conn.commit()
            conn.close()

            reopened = ProjectDB(path)
            entries = reopened.open_existing()
            reopened.close()

            self.assertEqual(entries[0]["intent"]["categories"], [])
            self.assertEqual(entries[0]["intent"]["extras"], {})
            self.assertEqual(entries[0]["stackTrace"], [])
            self.assertIsNone(entries[0]["original_intent"])
            self.assertEqual(len(reopened.load_warnings), 4)

    def test_project_info_is_key_value_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "project.noxen")
            db = ProjectDB(path)
            db.create("project")
            db.set_info("target", "com.example.app")
            db.close()

            conn = sqlite3.connect(path)
            rows = dict(conn.execute("SELECT key, value FROM project_info").fetchall())
            conn.close()

            self.assertEqual(rows["name"], "project")
            self.assertEqual(rows["target"], "com.example.app")

    def test_update_modified_intent_persists_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "project.noxen")
            db = ProjectDB(path)
            db.create("project")
            intent_id = db.save_intent({
                "timestamp": "2026-04-29T10:00:00+00:00",
                "class": "com.example.MainActivity",
                "method": "startActivity",
                "intent": {
                    "action": "old.action",
                    "data": "old:data",
                    "mimeType": "text/plain",
                    "flags": 1,
                    "categories": [],
                    "extras": {},
                },
            })
            db.update_modified_intent(
                intent_id,
                {
                    "action": "old.action", "data": "old:data",
                    "mimeType": "text/plain", "flags": 1,
                },
                {
                    "action": "new.action", "data": "new:data",
                    "mimeType": "application/pdf", "flags": 17,
                    "categories": [], "extras": {},
                },
            )
            db.close()

            reopened = ProjectDB(path)
            entries = reopened.open_existing()
            reopened.close()

            self.assertEqual(entries[0]["intent"]["flags"], 17)
            self.assertEqual(entries[0]["intent"]["mimeType"], "application/pdf")
            self.assertEqual(entries[0]["original_intent"]["flags"], 1)

    def test_modification_warning_survives_project_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "project.noxen")
            db = ProjectDB(path)
            db.create("project")
            intent_id = db.save_intent({
                "timestamp": "2026-10-14T08:00:00+00:00",
                "intent": {"action": "old", "extras": {}, "categories": []},
            })
            db.update_modification_error(intent_id, "Result could not be verified")
            db.update_outcome(intent_id, "forwarded")
            db.close()

            reopened = ProjectDB(path)
            entries = reopened.open_existing()
            reopened.close()
            self.assertEqual(entries[0]["modification_error"], "Result could not be verified")
            self.assertEqual(entries[0]["outcome"], "forwarded")


if __name__ == "__main__":
    unittest.main()
