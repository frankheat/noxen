import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from noxen.db import ProjectDB
from noxen.filters import FilterManager
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

    def test_invalid_project_info_json_falls_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "project.noxen")
            db = ProjectDB(path)
            db.create("project")
            db.set_info("intercept_filters", "{not-json")
            db.set_info("history_filters", '{"bad": "shape"}')
            db.set_info("history_columns", '{"bad": "shape"}')

            self.assertEqual(db.load_intercept_filters(), [])
            self.assertEqual(db.load_history_filters(), [])
            self.assertIsNone(db.load_history_columns())
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
                    "flags": 1,
                    "categories": [],
                    "extras": {},
                },
            })
            db.update_modified_intent(
                intent_id,
                {"action": "old.action", "data": "old:data", "flags": 1},
                {"action": "new.action", "data": "new:data", "flags": 17, "categories": [], "extras": {}},
            )
            db.close()

            reopened = ProjectDB(path)
            entries = reopened.open_existing()
            reopened.close()

            self.assertEqual(entries[0]["intent"]["flags"], 17)
            self.assertEqual(entries[0]["original_intent"]["flags"], 1)


if __name__ == "__main__":
    unittest.main()
