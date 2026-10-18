import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class SettingsIsolationMixin:
    """Give every UI test real settings I/O in its own temporary directory."""

    def setUp(self):
        super().setUp()
        directory = tempfile.TemporaryDirectory(prefix="noxen-ui-test-")
        self.addCleanup(directory.cleanup)
        self.settings_path = Path(directory.name) / "settings.txt"
        settings_path = patch("noxen.settings.settings_file_path", return_value=self.settings_path)
        settings_path.start()
        self.addCleanup(settings_path.stop)


class IsolatedAppTestCase(SettingsIsolationMixin, unittest.IsolatedAsyncioTestCase):
    pass
