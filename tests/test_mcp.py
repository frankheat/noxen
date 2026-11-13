import asyncio
import json
import logging
from functools import wraps
import socket
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from textual.widgets import Input, TabbedContent

from noxen.app import NoxenApp
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
        self.app.query_one("#home_script_path", Input).value = "/tmp/custom.js"
        with self.assertRaisesRegex(OperationError, "extra_script_selected"):
            await self.service.connect(**args)

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
                        self.assertTrue({"refresh_devices", "resolve_interception", "set_intercept"} <= names)
                        status = await client.call_tool("get_status")
                        self.assertFalse(status.isError)
                        self.assertEqual(status.structuredContent["instance"], self.service.instance)
                        self.capture("real-protocol")
                        result = await client.call_tool("list_history", {"query": "real-protocol"})
                        self.assertEqual(result.structuredContent["events"][0]["action"], "real-protocol")
                        event_id = result.structuredContent["events"][0]["id"]
                        self.app._init_session(SimpleNamespace())
                        session = self.app.frida_session
                        self.app._on_intercept_display("", event_id, "http-hold")
                        self.app.set_intercept_state(True)
                        token = self.service.connection_token()
                        with patch.object(session, "is_ready", return_value=True), patch.object(
                            session, "forward_with_mods", return_value=True
                        ) as forward, patch.object(session, "intercept_off_with_mods", return_value=True) as off:
                            resolved = await client.call_tool("resolve_interception", {
                                "action": "forward", "decision_id": "http-hold", "expected_connection": token,
                            })
                            self.assertFalse(resolved.isError)
                            self.assertFalse(resolved.structuredContent["held"])
                            forward.assert_called_once_with([], "http-hold")
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
                        self.service.allow_control = False
                        denied = await client.call_tool("disconnect", {
                            "expected_connection": self.service.connection_token()})
                        self.assertTrue(denied.isError)
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
