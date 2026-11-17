"""Controls for the MCP endpoint owned by this running application."""

import asyncio
import json

from textual.containers import Horizontal, VerticalScroll
from textual.widgets import Button, Input, Label, Rule, Switch, TextArea

from noxen.mcp_server import MCPServer
from noxen.modals import ModalButton


class MCPPane(VerticalScroll):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.server = None
        self._config_text = None
        self._view_state = None

    def compose(self):
        yield Label("MCP server", classes="mcp_title")
        with Horizontal(id="mcp_status_row"):
            yield Label("Status", classes="mcp_field_label")
            yield Label("Stopped", id="mcp_state", markup=False)
        with Horizontal(classes="mcp_controls"):
            yield Label("Port", classes="mcp_field_label")
            yield Input("8765", type="integer", id="mcp_port", select_on_focus=False, classes="field")
            yield ModalButton("Start", id="mcp_start", classes="confirm")
            yield ModalButton("Stop", id="mcp_stop", classes="danger", disabled=True)
        with Horizontal(classes="mcp_controls"):
            with Horizontal(id="mcp_control_group", classes="switch-control"):
                yield Switch(False, id="mcp_allow_control",
                             tooltip="Allow clients to rescan devices and control Frida, Intercept, and Monitor profiles.")
                yield Label("Allow control", classes="switch-control-label")
        yield Label(
            "Clients share this project and Frida session. Stopping MCP keeps Frida connected.",
            id="mcp_help",
        )
        yield Rule(classes="section_separator")
        yield Label("Client connection", classes="mcp_title")
        yield Label("Start the server to show its URL and authorization header.", id="mcp_empty")
        config = TextArea("", id="mcp_config", read_only=True, soft_wrap=True,
                          show_cursor=False, highlight_cursor_line=False)
        config.match_cursor_bracket = False
        yield config
        yield Label("", id="mcp_activity", markup=False)

    def on_mount(self):
        self.set_interval(0.2, self.refresh_server)

    def on_switch_changed(self, event: Switch.Changed):
        if event.switch.id == "mcp_allow_control":
            event.stop()
            self.app.mcp_service.allow_control = event.value

    def on_button_pressed(self, event: Button.Pressed):
        event.stop()
        if event.button.id == "mcp_stop":
            self.stop_server()
        elif event.button.id == "mcp_start":
            try:
                port = int(self.query_one("#mcp_port", Input).value)
                if not 1 <= port <= 65535:
                    raise ValueError
            except ValueError:
                self.app.notify("Use a port between 1 and 65535", severity="error")
                return
            if self.server and self.server.state != "stopped":
                return
            self.app.mcp_service.enabled = True
            self.server = MCPServer(self.app.mcp_service, asyncio.get_running_loop(), port)
            self.server.start()
        self.refresh_server()

    def stop_server(self):
        self.app.mcp_service.enabled = False
        if self.server:
            self.server.stop()

    def refresh_server(self):
        server = self.server
        if server is None:
            return
        state = server.state if server else "stopped"
        view_state = (id(server), state, server.error, server.port, server.requests, server.last_operation)
        if view_state == self._view_state:
            return
        self._view_state = view_state
        active = state != "stopped"
        self.query_one("#mcp_start", Button).disabled = active
        self.query_one("#mcp_stop", Button).disabled = not active
        self.query_one("#mcp_port", Input).disabled = active
        if server and state == "stopped":
            self.app.mcp_service.enabled = False
        message = server.error if server and server.error else state.capitalize()
        if state == "running":
            message += f" · {server.url}"
        self.query_one("#mcp_state", Label).update(message)
        config = (json.dumps({"url": server.url,
                              "headers": {"Authorization": f"Bearer {server.token}"}}, indent=2)
                  if state == "running" else "")
        self.query_one("#mcp_config").display = state == "running"
        self.query_one("#mcp_empty").display = state != "running"
        if config != self._config_text:
            self.query_one("#mcp_config", TextArea).load_text(config)
            self._config_text = config
        activity = self.query_one("#mcp_activity", Label)
        activity.display = bool(server.requests)
        activity.update(f"Requests: {server.requests} · Last operation: {server.last_operation or 'none'}")

    async def on_unmount(self):
        self.stop_server()
        if self.server:
            await self.server.wait_stopped()
