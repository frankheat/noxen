import asyncio
import json
import logging
from functools import wraps
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from textual.widgets import Input, Switch, TabbedContent

from noxen.app import NoxenApp
from noxen.frida_session import ModificationResume
from noxen.mcp_server import MCPServer
from noxen.mcp_service import OperationError, json_value
from noxen.mcp_ui import MCPPane
from noxen.monitor_ui import MonitorPane
from tests.ui_test_case import IsolatedAppTestCase


async def wait_for(predicate):
    async def poll():
        while not predicate():
            await asyncio.sleep(0.02)
    await asyncio.wait_for(poll(), 8)


def with_app(test):
    @wraps(test)
    async def run(self):
        with tempfile.TemporaryDirectory() as directory:
            self.app = NoxenApp(SimpleNamespace(project=None, new_project=directory + "/test",
                                                skip_device_scan=True))
            async with self.app.run_test(size=(110, 40)) as self.pilot:
                self.service = self.app.mcp_service
                self.service.enabled = True
                self.service.allow_control = True
                await test(self)
    return run


class MCPAppTestCase(IsolatedAppTestCase):
    def capture(self, action):
        return self.app._on_history_intent({"className": "test.Main", "methodName": "getIntent",
                                           "infoIntent": {"action": action, "component": "test/.Main"}}, 1)


class MCPServiceTests(MCPAppTestCase):
    @with_app
    async def test_export_history_preserves_full_entries_and_continues_at_size_limit(self):
        first, excluded, last = self.capture("SHOW"), self.capture("HIDE"), self.capture("SHOW")
        with self.app._history_lock:
            entries = {entry["id"]: entry for entry in self.app._all_intents}
            entries[last]["intent"]["extras"] = {"body": {"type": "string", "value": "♣" * 130}}
            entries[last]["original_intent"] = {"action": "ORIGINAL"}
            entries[first]["intent"]["extras"] = {"body": {"type": "string", "value": "♣" * 130}}
        state = await self.service.filters("history")
        state = await self.service.set_filters(
            "history", [{"id": 1, "type": "focus", "rule": {"action": "SHOW"}}],
            state["revision"], self.service.connection_token(),
        )
        revision = state["revision"]
        with patch("noxen.mcp_service.MAX_RESULT_BYTES", 2000):
            page = await self.service.invoke("export_history", filter_revision=revision)
            self.assertEqual([entry["id"] for entry in page["events"]], [last])
            self.assertEqual(page["events"][0]["original_intent"], {"action": "ORIGINAL"})
            self.assertEqual(page["events"][0]["intent"]["extras"]["body"]["value"], "♣" * 130)
            following = await self.service.invoke(
                "export_history", filter_revision=revision, epoch=page["epoch"], before_id=page["next_before_id"],
            )
            self.assertEqual([entry["id"] for entry in following["events"]], [first])
            self.assertIsNone(following["next_before_id"])
        with patch("noxen.mcp_service.MAX_RESULT_BYTES", 500):
            with self.assertRaisesRegex(OperationError, f"result_too_large: History event #{last}"):
                await self.service.invoke("export_history", filter_revision=revision)
        self.assertIn(excluded, [entry["id"] for entry in (await self.service.export_history())["events"]])

    @with_app
    async def test_input_anr_bypass_uses_home_switch_and_reports_installation_state(self):
        switch = self.app.query_one("#home_system_anr_bypass", Switch)
        token = self.service.connection_token()
        ready = {"state": "active", "installed_overloads": 3}
        bypass = SimpleNamespace(installation_status=lambda: ready, cleanup=lambda: None)
        self.assertEqual((await self.service.status())["input_anr_bypass"]["state"], "disabled")
        self.service.allow_control = False
        with self.assertRaisesRegex(OperationError, "control_disabled"):
            await self.service.set_input_anr_bypass(True, token)
        self.service.allow_control = True
        with patch.object(self.app, "_ensure_system_anr_bypass") as attach:
            status = await self.service.set_input_anr_bypass(True, token)
            self.assertTrue(switch.value)
            self.assertEqual(status["input_anr_bypass"]["state"], "waiting_for_connection")
            attach.assert_not_called()
            await self.service.set_input_anr_bypass(False, token)
            self.app._connection_state = "connected"
            self.app._session_device_id = "emulator"
            token = self.service.connection_token()
            attach.side_effect = lambda _: setattr(self.app, "system_server_session", bypass)
            status = await self.service.set_input_anr_bypass(True, token)
            self.assertEqual(status["input_anr_bypass"], {"enabled": True, **ready})
            await self.service.set_input_anr_bypass(True, token)
            attach.assert_called_once_with("emulator")
            switch.value = False
            await wait_for(lambda: self.app.system_server_session is None)
            self.assertEqual((await self.service.status())["input_anr_bypass"]["state"], "disabled")

    @with_app
    async def test_project_filters_are_persisted_and_can_scope_history(self):
        shown, hidden = self.capture("SHOW"), self.capture("HIDE")
        before = await self.service.filters("history")
        token = self.service.connection_token()
        filters = [{"id": 1, "type": "focus", "rule": {"action": "SHOW"}}]
        result = await self.service.set_filters("history", filters, before["revision"], token)
        self.assertEqual(self.app.db.load_history_filters(), result["filters"])
        self.assertEqual((await self.service.filters("intercept"))["filters"], [])
        page = await self.service.history(filter_revision=result["revision"])
        self.assertEqual([row["id"] for row in page["events"]], [shown])
        self.assertEqual([row["id"] for row in (await self.service.history())["events"]], [hidden, shown])
        with self.assertRaisesRegex(OperationError, "filters_changed"):
            await self.service.history(filter_revision=before["revision"])
        with self.assertRaisesRegex(OperationError, "invalid_filter"):
            await self.service.set_filters("history", filters * 2, result["revision"], token)
        self.assertEqual(self.app.db.load_history_filters(), result["filters"])

    @with_app
    async def test_restore_monitor_defaults_preserves_custom_hooks_and_can_restore_a_profile(self):
        state = await self.service.profiles()
        token = self.service.connection_token()
        original = state["profiles"][0]
        profile_id = original["id"]
        custom = {"class": "dev.example.Test", "method": "test", "args": []}
        saved = await self.service.save_monitor_profile({**original, "hooks": [custom]}, state["revision"], token)
        restored = await self.service.restore_monitor_defaults(profile_id, saved["revision"], token)
        self.assertEqual(restored["restored_hooks"], len(original["hooks"]))
        state = await self.service.profiles()
        self.assertEqual(state["profiles"][0]["hooks"][0]["class"], custom["class"])
        removed = await self.service.remove_monitor_profile(profile_id, restored["revision"], token)
        self.assertIn(profile_id, (await self.service.profiles())["missing_builtin_profiles"])
        await self.service.restore_monitor_defaults(profile_id, removed["revision"], token)
        self.assertIn(original, (await self.service.profiles())["profiles"])

    @with_app
    async def test_monitor_batch_is_atomic_and_custom_hook_requires_fresh_revision(self):
        profiles = (await self.service.profiles())["profiles"]
        first, second = profiles[:2]
        revision = self.service.profile_revision()
        token = self.service.connection_token()
        epoch = self.service.epoch("monitor")
        with self.assertRaisesRegex(OperationError, "not_found"):
            await self.service.set_profiles_enabled(
                {first["id"]: not first["enabled"], "missing": True}, revision, token,
            )
        self.assertEqual(self.service.profile_revision(), revision)

        result = await self.service.set_profiles_enabled(
            {first["id"]: not first["enabled"], second["id"]: not second["enabled"]}, revision, token,
        )
        self.assertEqual(self.service.epoch("monitor"), epoch)
        hook = {"class": "dev.example.Target", "method": "record", "args": ["java.lang.String"]}
        with self.assertRaisesRegex(OperationError, "profiles_changed"):
            await self.service.add_monitor_hook(first["id"], hook, revision, token)
        result = await self.service.add_monitor_hook(first["id"], hook, result["revision"], token)
        self.assertEqual(result["signature"], "dev.example.Target.record(java.lang.String)")
        saved = json.loads(self.app.db.get_info("monitor_profiles"))["profiles"]
        self.assertEqual(saved[0]["enabled"], not first["enabled"])
        self.assertEqual(saved[1]["enabled"], not second["enabled"])
        self.assertEqual(saved[0]["hooks"][-1]["method"], "record")
        with self.assertRaisesRegex(OperationError, "duplicate_hook"):
            await self.service.add_monitor_hook(first["id"], hook, result["revision"], token)

    @with_app
    async def test_session_logs_exclude_messages_from_retired_connection(self):
        self.app._init_session(SimpleNamespace())
        old_session = self.app.frida_session
        old_session.log_cb("old session")
        self.app._init_session(SimpleNamespace())
        self.app.frida_session.log_cb("active session")
        old_session.log_cb("late callback")
        session = await self.service.logs(scope="session")
        self.assertEqual(session["entries"], ["active session"])
        application = await self.service.logs()
        self.assertEqual(application["entries"][-3:], ["old session", "active session", "late callback"])

    @with_app
    async def test_wait_for_interception_skips_old_hold_and_wakes_for_new_one(self):
        self.app.update_intercept_button(True)
        token = self.service.connection_token()
        first, second = self.capture("FIRST"), self.capture("SECOND")
        self.app._on_intercept_display("", first, "first")
        self.app.set_intercept_state(True)
        current = await self.service.wait_for_interception(token)
        self.assertEqual(current["decision_id"], "first")

        waiting = asyncio.create_task(self.service.wait_for_interception(token, "first"))
        await asyncio.sleep(0)
        self.assertFalse(waiting.done())
        self.app._on_intercept_display("", second, "second")
        self.app.set_intercept_state(True)
        result = await asyncio.wait_for(waiting, 1)
        self.assertEqual(result["decision_id"], "second")
        self.assertFalse(result["timed_out"])
        self.assertTrue((await self.service.wait_for_interception(token, "second", 10))["timed_out"])

        waiting = asyncio.create_task(self.service.wait_for_interception(token, "second"))
        await asyncio.sleep(0)
        self.service.enabled = False
        with self.assertRaisesRegex(OperationError, "server_stopped"):
            await asyncio.wait_for(waiting, 1)

    @with_app
    async def test_list_processes_uses_discovered_device_and_filters_by_name(self):
        emulator = SimpleNamespace(id="emulator")
        process = SimpleNamespace(pid=123, name="Example App")
        device = SimpleNamespace(enumerate_processes=lambda: [
            SimpleNamespace(pid=5, name="system_server"), process,
        ], enumerate_applications=lambda: [SimpleNamespace(pid=123, identifier="dev.example")])
        self.app._home_devices = [emulator]
        with patch("frida.get_device", return_value=device) as resolve:
            result = await self.service.list_processes(
                "emulator", self.service.connection_token(), query="DEV.EXAMPLE",
            )
        resolve.assert_called_once_with("emulator")
        self.assertEqual(result, {"processes": [
            {"pid": 123, "name": "Example App", "package": "dev.example"},
        ], "total_matches": 1})

    @with_app
    async def test_list_applications_includes_stopped_packages(self):
        device = SimpleNamespace(enumerate_applications=lambda: [
            SimpleNamespace(pid=23, identifier="dev.example.running", name="Example Running"),
            SimpleNamespace(pid=0, identifier="dev.example.idle", name="Example Idle"),
        ])
        self.app._home_devices = [SimpleNamespace(id="emulator")]
        with patch("frida.get_device", return_value=device) as resolve:
            result = await self.service.list_applications(
                "emulator", self.service.connection_token(), query="EXAMPLE", limit=1,
            )
        resolve.assert_called_once_with("emulator")
        self.assertEqual(result, {"applications": [
            {"pid": None, "name": "Example Idle", "package": "dev.example.idle"},
        ], "total_matches": 2})

    @with_app
    async def test_refresh_devices_updates_home_and_returns_new_scan(self):
        device = SimpleNamespace(id="emulator-5554", name="Pixel", type="usb")
        with patch("noxen.app.scan_devices", return_value=[device]), patch.object(
            self.app, "_populate_target_apps"
        ):
            result = await self.service.refresh_devices(self.service.connection_token())
        self.assertEqual(result["devices"][0]["id"], device.id)
        self.assertEqual(self.app.query_one("#home_device").value, device.id)

    @with_app
    async def test_intercept_decision_rejects_stale_hold_and_preserves_new_hold(self):
        self.app._init_session(SimpleNamespace())
        session = self.app.frida_session
        first, second = self.capture("FIRST"), self.capture("SECOND")
        self.app._on_intercept_display("", first, "first")
        self.app.set_intercept_state(True)

        def drop(decision_id):
            self.assertEqual(decision_id, "first")
            self.app._on_intercept_display("", second, "second")
            return True

        with patch.object(session, "is_ready", return_value=True), patch.object(session, "drop", side_effect=drop) as rpc:
            token = self.service.connection_token()
            with self.assertRaisesRegex(OperationError, "hold_changed"):
                await self.service.resolve_interception("drop", "old", token)
            self.app._staged_mods.append(("action", "", "draft", ""))
            with self.assertRaisesRegex(OperationError, "draft_pending"):
                await self.service.resolve_interception("drop", "first", token)
            rpc.assert_not_called()
            self.app._staged_mods.clear()
            result = await self.service.resolve_interception("drop", "first", token)
        self.assertEqual(result["resolved_decision_id"], "first")
        self.assertEqual(result["decision_id"], "second")
        self.assertTrue(result["held"])
        self.assertEqual(self.app._all_intents[0]["outcome"], "dropped")

    @with_app
    async def test_history_search_paging_details_and_clear_invalidates_cursor(self):
        ids = [self.capture("MATCH"), self.capture("other"), self.capture("MATCH")]
        page = await self.service.history(query="match", limit=1)
        self.assertEqual(page["events"][0]["id"], ids[2])
        self.assertEqual(page["events"][0]["component"], "test/.Main")
        self.assertTrue(page["events"][0]["timestamp"])
        older = await self.service.history(query="match", before_id=page["next_before_id"],
                                           epoch=page["epoch"], limit=1)
        self.assertEqual(older["events"][0]["id"], ids[0])
        detail = await self.service.intent(ids[0], page["epoch"])
        detail["intent"]["intent"]["action"] = "mutated"
        self.assertEqual(self.app._all_intents[0]["intent"]["action"], "MATCH")
        self.app.action_clear_history()
        with self.assertRaisesRegex(OperationError, "events_cleared"):
            await self.service.intent(ids[0], page["epoch"])
        with self.assertRaisesRegex(OperationError, "invalid_cursor"):
            await self.service.history(before_id=ids[2])

    @with_app
    async def test_monitor_queries_do_not_confuse_local_id_with_database_id(self):
        self.app.db.save_monitor_batch("one", "now", [
            {"id": 99, "class": "test.One", "method": "read", "args": ["needle"]},
            {"id": 99, "class": "test.Two", "method": "read", "args": ["needle"]},
        ], 0, 0, "complete")
        page = await self.service.monitor_events(query="needle", limit=1)
        event_id = page["events"][0]["id"]
        self.assertNotEqual(event_id, 99)
        detail = await self.service.monitor_event(event_id, page["epoch"])
        self.assertEqual(detail["event"]["class"], "test.Two")
        older = await self.service.monitor_events(before_id=page["next_before_id"], epoch=page["epoch"])
        self.assertEqual(older["events"][0]["class"], "test.One")
        await self.app.query_one(MonitorPane).clear_events().wait()
        with self.assertRaisesRegex(OperationError, "events_cleared"):
            await self.service.monitor_event(event_id, page["epoch"])

    @with_app
    async def test_profile_changes_visible_persisted_and_conflict_checked(self):
        pane = self.app.query_one(MonitorPane)
        before = await self.service.profiles()
        profile = pane.profiles[0]
        desired = not profile["enabled"]
        args = dict(profile_id=profile["id"], enabled=desired,
                    expected_revision=before["revision"], expected_connection=self.service.connection_token())
        self.service.allow_control = False
        with self.assertRaisesRegex(OperationError, "control_disabled"):
            await self.service.set_profile_enabled(**args)
        self.service.allow_control = True
        await self.service.set_profile_enabled(**args)
        self.assertEqual(pane.profiles[0]["enabled"], desired)
        saved = json.loads(self.app.db.get_info("monitor_profiles"))
        self.assertEqual(saved["profiles"][0]["enabled"], desired)
        with self.assertRaisesRegex(OperationError, "profiles_changed"):
            await self.service.set_profile_enabled(**args)

    @with_app
    async def test_connect_uses_shared_start_and_rechecks_state_after_loading(self):
        self.app._home_devices = [SimpleNamespace(id="emulator", name="test", type="usb")]
        token = self.service.connection_token()
        args = dict(device_id="emulator", mode="spawn", target="dev.noxen.playground", expected_connection=token)
        started = threading.Event()
        release = threading.Event()

        def loader(path):
            started.set()
            release.wait(3)
            return object()

        with patch("noxen.mcp_service.load_hook_config", side_effect=loader), \
                patch.object(self.app, "_start_validated_connection") as start:
            task = asyncio.create_task(self.service.connect(**args))
            await wait_for(started.is_set)
            self.app._connection_generation += 1
            release.set()
            with self.assertRaisesRegex(OperationError, "state_changed"):
                await task
            start.assert_not_called()
        args["expected_connection"] = self.service.connection_token()
        with patch.object(self.app, "_start_validated_connection") as start:
            await self.service.connect(**args)
            config = start.call_args.args[1]
            self.assertEqual(config.spawn_package, "dev.noxen.playground")
            self.assertIsNotNone(config.validated_hooks)
        with tempfile.TemporaryDirectory() as directory, patch.object(
            self.app, "_start_validated_connection"
        ) as start:
            path = Path(directory) / "custom.js"
            script_input = self.app.query_one("#home_script_path", Input)
            script_input.value = str(path)
            with self.assertRaisesRegex(OperationError, "invalid_extra_script"):
                await self.service.connect(**args)
            start.assert_not_called()
            path.write_text("send('home');", encoding="utf-8")
            await self.service.connect(**args)
            self.assertEqual(start.call_args.args[1].extra_script_source.code, "send('home');")
            await self.service.connect(**args, extra_script="send('inline');")
            self.assertEqual(start.call_args.args[1].extra_script_source.code, "send('inline');")
            await self.service.connect(**args, extra_script="")
            self.assertIsNone(start.call_args.args[1].extra_script_source)
            self.assertEqual(script_input.value, str(path))

    @with_app
    async def test_refresh_app_info_publishes_the_shared_snapshot(self):
        token = self.service.connection_token()
        with self.assertRaisesRegex(OperationError, "session_not_ready"):
            await self.service.refresh_app_info(token)
        self.app._init_session(SimpleNamespace())
        session = self.app.frida_session
        snapshot = {"identity": {"package": "dev.example"}}
        with patch.object(session, "is_ready", return_value=True), patch.object(
            session, "get_app_info", return_value=snapshot,
        ):
            result = await self.service.refresh_app_info(token)
        self.assertEqual(result["snapshot"], snapshot)
        self.assertEqual(result, await self.service.app_info())
        self.app.frida_session = None

    @with_app
    async def test_clear_events_checks_epoch_and_shares_the_ui_state(self):
        self.capture("remove")
        token = self.service.connection_token()
        history_epoch = self.service.epoch("history")
        monitor_epoch = self.service.epoch("monitor")
        cleared = await self.service.clear_events("history", history_epoch, token)
        self.assertNotEqual(cleared["epoch"], history_epoch)
        self.assertEqual((await self.service.history())["events"], [])
        self.assertEqual(self.service.epoch("monitor"), monitor_epoch)
        with self.assertRaisesRegex(OperationError, "events_cleared"):
            await self.service.clear_events("history", history_epoch, token)
        async with self.service.pane.recording_lock:
            pending = asyncio.create_task(self.service.clear_events("monitor", monitor_epoch, token))
            await asyncio.sleep(0)
            self.service.allow_control = False
        with self.assertRaisesRegex(OperationError, "control_disabled"):
            await pending
        self.assertEqual(self.service.epoch("monitor"), monitor_epoch)
        self.service.allow_control = True
        cleared = await self.service.clear_events("monitor", monitor_epoch, token)
        self.assertNotEqual(cleared["epoch"], monitor_epoch)
        await self.service.clear_logs(token)
        self.assertEqual((await self.service.logs())["entries"], [])

    @with_app
    async def test_connect_with_inline_hooks_validates_and_uses_the_requested_receiver(self):
        self.app._home_devices = [SimpleNamespace(id="emulator", name="test", type="usb")]
        args = dict(device_id="emulator", mode="spawn", target="dev.example",
                    expected_connection=self.service.connection_token())
        hook = {"clazz": "dev.example.Receiver", "method": "onReceive",
                "args": ["android.content.Context", "android.content.Intent"]}
        with patch.object(self.app, "_start_validated_connection") as start:
            with self.assertRaisesRegex(ValueError, "MCP hook config"):
                await self.service.connect(**args, hooks=[{"method": "onReceive"}])
            start.assert_not_called()
            await self.service.connect(**args, hooks=[hook])
            config = start.call_args.args[1]
            self.assertIn(hook, config.validated_hooks.hooks)
            self.assertEqual(config.validated_hooks.custom_count, 1)

    @with_app
    async def test_stopped_service_does_not_accept_work(self):
        self.app.write_log("[dim]hooks[/dim] ERROR Missing overload")
        self.assertEqual((await self.service.invoke("get_logs", limit=1))["entries"],
                         ["hooks ERROR Missing overload"])
        self.service.enabled = False
        with self.assertRaisesRegex(OperationError, "server_stopped"):
            await self.service.invoke("get_status")

    @with_app
    async def test_stopped_request_cannot_connect_after_server_restart(self):
        self.app._home_devices = [SimpleNamespace(id="emulator", name="test", type="usb")]
        started, release = threading.Event(), threading.Event()
        access = {"open": True}

        def loader(path):
            started.set()
            release.wait(3)
            return object()

        with patch("noxen.mcp_service.load_hook_config", side_effect=loader), \
                patch.object(self.app, "_start_validated_connection") as start:
            task = asyncio.create_task(self.service.invoke(
                "connect", _access_open=lambda: access["open"], device_id="emulator",
                mode="spawn", target="dev.noxen.playground",
                expected_connection=self.service.connection_token(),
            ))
            await wait_for(started.is_set)
            access["open"] = False
            # A new server may have reenabled the shared service already.
            self.service.enabled = True
            release.set()
            with self.assertRaisesRegex(OperationError, "server_stopped"):
                await task
            start.assert_not_called()

    @with_app
    async def test_profile_save_failure_does_not_report_success(self):
        original = await self.service.profiles()
        profile = original["profiles"][0]
        with patch.object(self.app.db, "set_info", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OperationError, "save_failed"):
                await self.service.set_profile_enabled(
                    profile["id"], not profile["enabled"], original["revision"], self.service.connection_token(),
                )
        self.assertEqual((await self.service.profiles())["revision"], original["revision"])

    @with_app
    async def test_mcp_tab_layout_at_supported_widths(self):
        self.app.query_one("#main_tabs", TabbedContent).active = "tab_mcp"
        pane = self.app.query_one(MCPPane)
        for theme in ("noxen-dark", "noxen-light"):
            self.app.theme = theme
            for width in (60, 80, 110, 190):
                with self.subTest(theme=theme, width=width):
                    await self.pilot.resize_terminal(width, 40)
                    await self.pilot.pause()
                    port = pane.query_one("#mcp_port")
                    start = pane.query_one("#mcp_start")
                    stop = pane.query_one("#mcp_stop")
                    config = pane.query_one("#mcp_config")
                    self.assertEqual(port.region.width, 10)
                    self.assertEqual(start.region.x - port.region.right, 2)
                    self.assertEqual(stop.region.x - start.region.right, 1)
                    self.assertEqual(start.region.y, port.region.y)
                    self.assertEqual(start.region.height, port.region.height)
                    self.assertEqual(pane.query_one("#mcp_state").content_region.x, port.content_region.x)
                    self.assertLessEqual(stop.region.right, pane.content_region.right)
                    self.assertEqual(start.styles.border_top, self.app.query_one("#monitor_new").styles.border_top)
                    self.assertFalse(config.display)
                    self.assertTrue(pane.query_one("#mcp_empty").display)
                    try:
                        pane.server = SimpleNamespace(
                            state="running", error=None, port=8765, url="http://127.0.0.1:8765/mcp",
                            token="preview-token", requests=0, last_operation="",
                        )
                        pane.refresh_server()
                        await self.pilot.pause()
                        self.assertTrue(config.display)
                        self.assertFalse(pane.query_one("#mcp_empty").display)
                        self.assertGreater(config.content_region.width, 40)
                        self.assertEqual(config.styles.border_top[0], "")
                        self.assertIn("preview-token", config.text)
                        pane.server.state = "stopped"
                        pane.refresh_server()
                        await self.pilot.pause()
                        self.assertFalse(config.display)
                        self.assertNotIn("preview-token", config.text)
                    finally:
                        pane.server = None


class MCPValueTests(unittest.TestCase):
    def test_json_preserves_large_integer_nonfinite_and_controls(self):
        value = {"large": 9223372036854775807, "nan": float("nan"), "null": None,
                 "flag": True, "text": "a\n\u202eb"}
        safe = json_value(value)
        self.assertEqual(safe["large"]["$number"], "9223372036854775807")
        self.assertEqual(safe["nan"]["$number"], "nan")
        self.assertIs(safe["flag"], True)
        self.assertEqual(json.loads(json.dumps(safe, allow_nan=False))["text"], value["text"])


class MCPTransportTests(MCPAppTestCase):
    @with_app
    async def test_real_client_auth_control_stop_and_restart(self):
        import httpx
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        server = MCPServer(self.service, asyncio.get_running_loop(), port=0)
        root_handlers = logging.getLogger().handlers[:]
        server.start()
        try:
            await wait_for(lambda: server.state in ("running", "stopped"))
            self.assertIsNone(server.error)
            self.assertEqual(server.state, "running")
            async with httpx.AsyncClient() as http:
                self.assertEqual((await http.post(server.url, json={})).status_code, 401)
                bad_host = await http.post(server.url, json={}, headers={
                    "Authorization": f"Bearer {server.token}", "Host": "evil.example",
                    "Content-Type": "application/json",
                })
                self.assertIn(bad_host.status_code, (400, 421))
                bad_origin = await http.post(server.url, json={}, headers={
                    "Authorization": f"Bearer {server.token}", "Origin": "https://evil.example",
                    "Content-Type": "application/json",
                })
                self.assertEqual(bad_origin.status_code, 403)
            async with httpx.AsyncClient(headers={"Authorization": f"Bearer {server.token}"}) as http:
                async with streamable_http_client(server.url, http_client=http) as (read, write, _):
                    async with ClientSession(read, write) as client:
                        await client.initialize()
                        names = {t.name for t in (await client.list_tools()).tools}
                        self.assertIn("connect", names)
                        self.assertIn("get_interception", names)
                        self.assertTrue({"refresh_app_info", "clear_events", "clear_logs",
                                         "restore_monitor_defaults", "retry_monitor_hooks",
                                         "set_filters", "list_applications", "get_stack_settings", "set_stack_settings",
                                         "save_monitor_profile", "remove_monitor_profile"} <= names)
                        self.assertTrue({"refresh_devices", "resolve_interception", "set_intercept"} <= names)
                        status = await client.call_tool("get_status")
                        self.assertFalse(status.isError)
                        self.assertEqual(status.structuredContent["instance"], self.service.instance)
                        self.capture("real-protocol")
                        result = await client.call_tool("list_history", {"query": "real-protocol"})
                        self.assertEqual(result.structuredContent["events"][0]["action"], "real-protocol")
                        event_id = result.structuredContent["events"][0]["id"]
                        exported = await client.call_tool("export_history", {"query": "real-protocol"})
                        self.assertEqual(exported.structuredContent["events"][0]["intent"]["action"], "real-protocol")
                        bypass = await client.call_tool("set_input_anr_bypass", {
                            "enabled": True, "expected_connection": status.structuredContent["connection_token"],
                        })
                        self.assertEqual(bypass.structuredContent["input_anr_bypass"]["state"], "waiting_for_connection")
                        self.app._init_session(SimpleNamespace())
                        session = self.app.frida_session
                        self.app._on_intercept_display("", event_id, "http-hold")
                        self.app.set_intercept_state(True)
                        token = self.service.connection_token()
                        stack = await client.call_tool("set_stack_settings", {
                            "scope": "history", "enabled": True, "depth": 9,
                            "expected_connection": token,
                        })
                        self.assertFalse(stack.isError)
                        self.assertEqual(stack.structuredContent["history"], {"enabled": True, "depth": 9})
                        with patch.object(session, "is_ready", return_value=True), patch.object(
                            session, "get_app_info", return_value={"identity": {"package": "dev.example"}},
                        ):
                            info = await client.call_tool("refresh_app_info", {"expected_connection": token})
                        self.assertFalse(info.isError)
                        self.assertEqual(info.structuredContent["snapshot"]["identity"]["package"], "dev.example")
                        observed = dict(action="real-protocol", component="test/.Main", data=None,
                                        mimeType=None, flags=1, categories=["test.category"],
                                        extras={"amount": {"type": "java.lang.String", "value": "42"}})
                        with patch.object(session, "is_ready", return_value=True), patch.object(
                            session, "forward_with_mods",
                            return_value=ModificationResume(True, {"ok": True, "infoIntent": observed}),
                        ) as forward, patch.object(session, "intercept_off_with_mods", return_value=True) as off:
                            request = {
                                "action": "forward", "decision_id": "http-hold", "expected_connection": token,
                                "modifications": [
                                    {"type": "extra_add", "key": "amount", "value": "42", "extra_type": "string"},
                                    {"type": "cat_add", "value": "test.category"},
                                    {"type": "flag_add", "value": "0x1"},
                                ],
                            }
                            rejected = await client.call_tool("resolve_interception", {
                                **request, "modifications": [{"type": "extra_add", "key": "amount",
                                                              "value": "invalid", "extra_type": "int"}],
                            })
                            self.assertTrue(rejected.isError)
                            self.assertEqual(rejected.structuredContent["error"]["code"], "invalid_modification")
                            rejected = await client.call_tool("resolve_interception", {
                                **request, "modifications": [{"type": "flag_add", "value": "0x100000000"}],
                            })
                            self.assertTrue(rejected.isError)
                            self.assertEqual(rejected.structuredContent["error"]["code"], "invalid_modification")
                            forward.assert_not_called()
                            resolved = await client.call_tool("resolve_interception", request)
                            self.assertFalse(resolved.isError)
                            self.assertFalse(resolved.structuredContent["held"])
                            self.assertEqual(resolved.structuredContent["outcome"], "modified_forwarded")
                            self.assertIsNone(resolved.structuredContent["modification_error"])
                            forward.assert_called_once_with([
                                ("extra_add", "amount", "42", "string"),
                                ("cat_add", "", "test.category", ""),
                                ("flag_add", "", "1", ""),
                            ], "http-hold")
                            detail = await client.call_tool("get_intent", {
                                "event_id": event_id, "epoch": resolved.structuredContent["history_epoch"],
                            })
                            self.assertEqual(detail.structuredContent["intent"]["intent"]["extras"]["amount"]["value"], "42")
                            disabled = await client.call_tool("set_intercept", {
                                "enabled": False, "expected_connection": token,
                            })
                            self.assertFalse(disabled.isError)
                            self.assertFalse(disabled.structuredContent["enabled"])
                            off.assert_called_once_with([], None)
                        self.app.frida_session = None
                        profiles = (await client.call_tool("get_monitor_profiles")).structuredContent
                        profile = profiles["profiles"][0]
                        changed = await client.call_tool("set_monitor_profile_enabled", {
                            "profile_id": profile["id"], "enabled": not profile["enabled"],
                            "expected_revision": profiles["revision"],
                            "expected_connection": self.service.connection_token(),
                        })
                        self.assertFalse(changed.isError)
                        self.assertEqual(self.app.query_one(MonitorPane).profiles[0]["enabled"], not profile["enabled"])
                        revision = changed.structuredContent["revision"]
                        token = self.service.connection_token()
                        custom = {"id": "test-custom", "name": "Custom test", "enabled": False, "hooks": []}
                        saved = await client.call_tool("save_monitor_profile", {
                            "profile": custom, "expected_revision": revision, "expected_connection": token,
                        })
                        self.assertFalse(saved.isError)
                        self.assertIn(custom, json.loads(self.app.db.get_info("monitor_profiles"))["profiles"])
                        removed = await client.call_tool("remove_monitor_profile", {
                            "profile_id": custom["id"], "expected_revision": saved.structuredContent["revision"],
                            "expected_connection": token,
                        })
                        self.assertFalse(removed.isError)
                        self.assertNotIn(custom, json.loads(self.app.db.get_info("monitor_profiles"))["profiles"])
                        self.service.allow_control = False
                        denied = await client.call_tool("disconnect", {
                            "expected_connection": self.service.connection_token()})
                        self.assertTrue(denied.isError)
                        self.assertEqual(denied.structuredContent["error"]["code"], "control_disabled")
            self.assertEqual(self.app._connection_state, "disconnected")
        finally:
            server.stop()
            self.assertTrue(await server.wait_stopped())
            self.assertEqual(logging.getLogger().handlers, root_handlers)
        replacement = MCPServer(self.service, asyncio.get_running_loop(), port=server.port)
        self.assertNotEqual(replacement.token, server.token)
        replacement.start()
        try:
            await wait_for(lambda: replacement.state in ("running", "stopped"))
            self.assertEqual(replacement.state, "running", replacement.error)
        finally:
            replacement.stop()
            await replacement.wait_stopped()

    @with_app
    async def test_occupied_port_does_not_change_app_connection(self):
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            server = MCPServer(self.service, asyncio.get_running_loop(), occupied.getsockname()[1])
            server.start()
            await wait_for(lambda: server.state == "stopped")
            self.assertTrue(server.error)
            self.assertEqual(self.app._connection_state, "disconnected")
