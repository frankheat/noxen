import os
import tempfile
import unittest
from types import SimpleNamespace

from noxen.app import NoxenApp
from noxen.db import ProjectDB
from noxen.frida_session import ModificationResume
from noxen.rendering import payload_to_history_entry


class ModificationConfirmationTests(unittest.TestCase):
    def make_app(self, path):
        db = ProjectDB(path)
        db.create("session")
        entry = payload_to_history_entry({
            "className": "Example", "methodName": "startActivity",
            "infoIntent": {"action": "old", "data": None, "mimeType": None,
                           "flags": 0, "categories": [], "extras": {}},
        })
        entry["id"] = db.save_intent(entry)
        messages = []
        app = SimpleNamespace(
            db=db, _all_intents=[entry], _history_search_index={},
            _staged_mods=[], write_log=messages.append,
            notify=lambda *args, **kwargs: messages.append((args, kwargs)),
            call_from_thread=lambda callback: callback(),
            _clear_intercept_output=lambda _entry: None,
        )
        def update_outcome(intent_id, outcome):
            entry["outcome"] = outcome
            db.update_outcome(intent_id, outcome)
        app._update_outcome = update_outcome
        app._persist_history_update = lambda *args: NoxenApp._persist_history_update(app, *args)
        return app, entry, messages

    def test_partial_failure_persists_only_observed_changes_and_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "session.noxen")
            app, entry, messages = self.make_app(path)
            report = ModificationResume(True, {
                "ok": False, "error": "NumberFormatException",
                "infoIntent": {"action": "changed", "data": None, "mimeType": None,
                               "flags": 0, "categories": [], "extras": {}},
            })
            mods = [
                ("action", "", "changed", ""),
                ("extra_add", "bad", "invalid", "float"),
                ("extra_add", "later", "hello", "string"),
            ]
            NoxenApp._finalize_forward(app, entry["id"], entry, mods, report)
            self.assertEqual(entry["outcome"], "modified_forwarded")
            self.assertEqual(entry["intent"]["action"], "changed")
            self.assertEqual(entry["intent"]["extras"], {})
            self.assertIn("NumberFormatException", entry["modification_error"])
            self.assertTrue(messages)
            app.db.close()

            reopened = ProjectDB(path)
            rows = reopened.open_existing()
            reopened.close()
            self.assertEqual(rows[0]["intent"]["action"], "changed")
            self.assertEqual(rows[0]["intent"]["extras"], {})
            self.assertEqual(rows[0]["original_intent"]["action"], "old")
            self.assertIn("NumberFormatException", rows[0]["modification_error"])

    def test_missing_report_does_not_persist_requested_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "session.noxen")
            app, entry, _messages = self.make_app(path)
            NoxenApp._finalize_forward(
                app, entry["id"], entry,
                [("action", "", "requested", "")], ModificationResume(True),
            )
            self.assertEqual(entry["outcome"], "forwarded")
            self.assertEqual(entry["intent"]["action"], "old")
            self.assertIn("could not be verified", entry["modification_error"])
            app.db.close()
