import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from noxen.agent_loader import (
    PASSTHROUGH_AGENT,
    PASSTHROUGH_SYSTEM_SERVER_AGENT,
    load_agent_script,
    load_hook_config,
    load_json_hooks,
    load_system_server_script,
)


class AgentLoaderTests(unittest.TestCase):
    def test_load_json_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "hooks.json")
            with open(path, "w") as f:
                f.write('[{"clazz": "Example", "method": "run", "args": []}]')

            self.assertEqual(
                load_json_hooks(path),
                [{"clazz": "Example", "method": "run", "args": []}],
            )

    def test_load_hook_config_combines_default_and_custom_hooks(self):
        with self._temp_cwd() as tmp:
            os.makedirs("config")
            default = os.path.join(tmp, "config", "hooks.json")
            with open(default, "w") as f:
                f.write('[{"clazz": "Default", "method": "run", "args": []}]')
            custom = os.path.join(tmp, "custom.json")
            with open(custom, "w") as f:
                f.write('[{"clazz": "Custom", "method": "run", "args": []}]')

            with patch("noxen.agent_loader.DEFAULT_HOOKS_FILE", default):
                result = load_hook_config(custom)

            self.assertEqual([hook["clazz"] for hook in result.hooks], ["Default", "Custom"])
            self.assertEqual(result.messages, [])

    def test_load_hook_config_reports_invalid_custom_json(self):
        with self._temp_cwd():
            os.makedirs("config")
            default = os.path.abspath("config/hooks.json")
            with open(default, "w") as f:
                f.write("[]")
            with open("bad.json", "w") as f:
                f.write("{bad-json")

            with patch("noxen.agent_loader.DEFAULT_HOOKS_FILE", default):
                result = load_hook_config("bad.json")

            self.assertEqual(result.hooks, [])
            self.assertIn("Invalid JSON in bad.json", result.messages[0])

    def test_load_agent_script_prefers_bundle_and_appends_extra(self):
        with self._temp_cwd():
            os.makedirs("agent")
            bundle = os.path.abspath("agent/script_bundle.js")
            with open(bundle, "w") as f:
                f.write("bundle")
            with open("extra.js", "w") as f:
                f.write("extra")

            with patch("noxen.agent_loader.BUNDLE_SCRIPT_FILE", bundle):
                result = load_agent_script("extra.js")

            self.assertEqual(result.code, "bundle\n\nextra")
            self.assertEqual(result.messages, ["[dim]loader       [/dim] [dim]DEBUG[/dim] Extra script loaded: extra.js"])

    def test_load_agent_script_falls_back_to_source_without_bundle(self):
        with self._temp_cwd():
            os.makedirs("agent")
            bundle = os.path.abspath("agent/script_bundle.js")
            source = os.path.abspath("agent/script.js")
            with open(source, "w") as f:
                f.write("source")

            with patch("noxen.agent_loader.BUNDLE_SCRIPT_FILE", bundle):
                with patch("noxen.agent_loader.SOURCE_SCRIPT_FILE", source):
                    result = load_agent_script()

            self.assertEqual(result.code, "source")
            self.assertEqual(
                result.messages,
                [
                    "[dim]loader       [/dim] [yellow]WARN [/yellow] "
                    "agent/script_bundle.js not found; using agent/script.js (Frida >=17 unsupported)"
                ],
            )

    def test_load_agent_script_uses_passthrough_when_no_script_exists(self):
        with self._temp_cwd():
            with patch("noxen.agent_loader.BUNDLE_SCRIPT_FILE", os.path.abspath("agent/script_bundle.js")):
                with patch("noxen.agent_loader.SOURCE_SCRIPT_FILE", os.path.abspath("agent/script.js")):
                    result = load_agent_script()

            self.assertEqual(result.code, PASSTHROUGH_AGENT)
            self.assertEqual(
                result.messages,
                ["[dim]loader       [/dim] [yellow]WARN [/yellow] No agent script found; running in passthrough mode"],
            )

    def test_load_system_server_script_prefers_bundle(self):
        with self._temp_cwd():
            os.makedirs("agent")
            bundle = os.path.abspath("agent/system_server_bundle.js")
            with open(bundle, "w") as f:
                f.write("system bundle")

            with patch("noxen.agent_loader.SYSTEM_SERVER_BUNDLE_SCRIPT_FILE", bundle):
                result = load_system_server_script()

            self.assertEqual(result.code, "system bundle")
            self.assertEqual(result.messages, [])

    def test_load_system_server_script_uses_passthrough_when_missing(self):
        with self._temp_cwd():
            with patch(
                "noxen.agent_loader.SYSTEM_SERVER_BUNDLE_SCRIPT_FILE",
                os.path.abspath("agent/system_server_bundle.js"),
            ):
                with patch(
                    "noxen.agent_loader.SYSTEM_SERVER_SOURCE_SCRIPT_FILE",
                    os.path.abspath("agent/system_server.js"),
                ):
                    result = load_system_server_script()

            self.assertEqual(result.code, PASSTHROUGH_SYSTEM_SERVER_AGENT)
            self.assertEqual(
                result.messages,
                [
                    "[dim]loader       [/dim] [yellow]WARN [/yellow] "
                    "No system_server agent found; Input ANR bypass disabled"
                ],
            )

    def test_default_hooks_fall_back_to_packaged_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source" / "config" / "hooks.json"
            packaged = root / "runtime" / "config" / "hooks.json"
            packaged.parent.mkdir(parents=True)
            packaged.write_text('[{"clazz": "Packaged", "method": "run", "args": []}]', encoding="utf-8")

            with patch("noxen.agent_loader.SOURCE_DEFAULT_HOOKS_FILE", source):
                with patch("noxen.agent_loader.DEFAULT_HOOKS_FILE", source):
                    with patch("noxen.agent_loader.PACKAGED_DEFAULT_HOOKS_FILE", packaged):
                        result = load_hook_config()

            self.assertEqual([hook["clazz"] for hook in result.hooks], ["Packaged"])
            self.assertEqual(result.messages, [])

    def test_agent_scripts_fall_back_to_packaged_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_bundle = root / "source" / "agent" / "script_bundle.js"
            source_script = root / "source" / "agent" / "script.js"
            packaged_bundle = root / "runtime" / "agent" / "script_bundle.js"
            packaged_script = root / "runtime" / "agent" / "script.js"
            packaged_bundle.parent.mkdir(parents=True)
            packaged_bundle.write_text("packaged bundle", encoding="utf-8")
            packaged_script.write_text("packaged source", encoding="utf-8")

            with patch("noxen.agent_loader.SOURCE_BUNDLE_SCRIPT_FILE", source_bundle):
                with patch("noxen.agent_loader.BUNDLE_SCRIPT_FILE", source_bundle):
                    with patch("noxen.agent_loader.PACKAGED_BUNDLE_SCRIPT_FILE", packaged_bundle):
                        with patch("noxen.agent_loader.SOURCE_SCRIPT_FILE_DEFAULT", source_script):
                            with patch("noxen.agent_loader.SOURCE_SCRIPT_FILE", source_script):
                                with patch("noxen.agent_loader.PACKAGED_SOURCE_SCRIPT_FILE", packaged_script):
                                    result = load_agent_script()

            self.assertEqual(result.code, "packaged bundle")
            self.assertEqual(result.messages, [])

    def test_system_server_script_falls_back_to_packaged_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_bundle = root / "source" / "agent" / "system_server_bundle.js"
            source_script = root / "source" / "agent" / "system_server.js"
            packaged_bundle = root / "runtime" / "agent" / "system_server_bundle.js"
            packaged_script = root / "runtime" / "agent" / "system_server.js"
            packaged_bundle.parent.mkdir(parents=True)
            packaged_bundle.write_text("packaged system bundle", encoding="utf-8")
            packaged_script.write_text("packaged system source", encoding="utf-8")

            with patch("noxen.agent_loader.SOURCE_SYSTEM_SERVER_BUNDLE_SCRIPT_FILE", source_bundle):
                with patch("noxen.agent_loader.SYSTEM_SERVER_BUNDLE_SCRIPT_FILE", source_bundle):
                    with patch("noxen.agent_loader.PACKAGED_SYSTEM_SERVER_BUNDLE_SCRIPT_FILE", packaged_bundle):
                        with patch("noxen.agent_loader.SOURCE_SYSTEM_SERVER_SCRIPT_FILE", source_script):
                            with patch("noxen.agent_loader.SYSTEM_SERVER_SOURCE_SCRIPT_FILE", source_script):
                                with patch("noxen.agent_loader.PACKAGED_SYSTEM_SERVER_SOURCE_SCRIPT_FILE", packaged_script):
                                    result = load_system_server_script()

            self.assertEqual(result.code, "packaged system bundle")
            self.assertEqual(result.messages, [])

    def test_default_paths_are_independent_from_current_directory(self):
        with self._temp_cwd():
            hooks = load_hook_config()
            script = load_agent_script()
            system_script = load_system_server_script()

        self.assertEqual(hooks.messages, [])
        self.assertTrue(hooks.hooks)
        self.assertEqual(script.messages, [])
        self.assertNotEqual(script.code, PASSTHROUGH_AGENT)
        self.assertEqual(system_script.messages, [])
        self.assertNotEqual(system_script.code, PASSTHROUGH_SYSTEM_SERVER_AGENT)

    def _temp_cwd(self):
        return _TempCwd()


class _TempCwd:
    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._previous = os.getcwd()
        os.chdir(self._tmp.name)
        return self._tmp.name

    def __exit__(self, exc_type, exc, tb):
        os.chdir(self._previous)
        self._tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
