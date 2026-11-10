"""Monitor UI and bounded delivery; no Frida calls on the UI thread."""
import copy
import json
import sqlite3
import threading
from collections import deque
from datetime import datetime

from rich.text import Text
from textual import work
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Input, Label, Select, Static, TabbedContent, TabPane

from noxen.modals import ExtraKeyModal
from noxen.monitor import (MAX_EVENTS, enabled_hooks, event_detail, load_profiles, new_profile,
                           signature, validate_hook, validate_profiles)


class MonitorDialog(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Cancel")]
    DEFAULT_CSS = """
    MonitorDialog { align: center middle; }
    #monitor_dialog { width: 85%; max-width: 84; height: 90%; max-height: 28;
        background: $surface; border: solid $foreground-muted; padding: 0 2; }
    #monitor_dialog.profile-name-dialog { height: auto; max-height: 90%; }
    #monitor_dialog_body { height: 1fr; }
    .profile-name-dialog #monitor_dialog_body { height: auto; }
    #monitor_dialog_title { text-style: bold; }
    #monitor_dialog Label { height: auto; }
    #monitor_dialog Checkbox { height: 1; border: none; padding: 0; }
    #monitor_dialog .buttons { height: 3; align: right middle; }
    #monitor_dialog Button { width: auto; min-width: 12; margin-left: 1; }
    #monitor_error { color: $error; }
    """

    def __init__(self, hook=None, name=None):
        super().__init__()
        self.hook = copy.deepcopy(hook)
        self.profile_name = name

    def compose(self):
        is_profile = self.profile_name is not None
        with Vertical(id="monitor_dialog", classes="profile-name-dialog" if is_profile else ""):
            if is_profile:
                title = "Rename profile" if self.profile_name else "New profile"
            else:
                title = "Edit hook" if self.hook else "Add hook"
            yield Label(title, id="monitor_dialog_title")
            with VerticalScroll(id="monitor_dialog_body"):
                if is_profile:
                    yield Label("Profile name")
                    yield Input(self.profile_name, id="monitor_name", max_length=60)
                else:
                    yield from self.compose_hook_fields()
            error = Label("", id="monitor_error", markup=False)
            error.display = False
            yield error
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="monitor_cancel")
                yield Button("Save", id="monitor_save")

    def on_mount(self):
        selector = "#monitor_name" if self.profile_name is not None else "#monitor_class"
        self.query_one(selector, Input).focus()

    def compose_hook_fields(self):
        hook = self.hook or {}
        yield Label("Class")
        yield Input(hook.get("class", ""), placeholder="com.example.ReportManager", id="monitor_class")
        yield Label("Method ($init for constructors)")
        yield Input(hook.get("method", ""), placeholder="exportReport", id="monitor_method")
        yield Label("Argument types (comma-separated, blank for none)")
        yield Input(", ".join(hook.get("args", [])), placeholder="java.lang.String, boolean", id="monitor_args")
        for key, title, default in (("captureArguments", "Capture arguments", True),
                                    ("captureReturn", "Capture return value", True),
                                    ("captureStack", "Capture stack (up to 16 frames)", False)):
            yield Checkbox(title, hook.get(key, default), id=key)

    def on_button_pressed(self, event):
        event.stop()
        if event.button.id == "monitor_cancel":
            self.dismiss(None)
            return
        try:
            if self.profile_name is not None:
                name = self.query_one("#monitor_name", Input).value.strip()
                validate_profiles([new_profile(name)])
                self.dismiss(name)
            else:
                args = self.query_one("#monitor_args", Input).value.strip()
                h = {"class": self.query_one("#monitor_class", Input).value.strip(),
                     "method": self.query_one("#monitor_method", Input).value.strip(),
                     "args": args.split(",") if args else []}
                for key in ("captureArguments", "captureReturn", "captureStack"):
                    h[key] = self.query_one(f"#{key}", Checkbox).value
                self.dismiss(validate_hook(h))
        except ValueError as exc:
            error = self.query_one("#monitor_error", Label)
            error.update(str(exc))
            error.display = True


class MonitorPane(Vertical):
    HOOK_STATE_WIDTH = 13

    DEFAULT_CSS = """
    MonitorPane { height: 1fr; }
    MonitorPane .monitor_controls { height: 3; padding: 0 1; align: left middle; background: $panel; }
    MonitorPane .monitor_controls Button { width: auto; min-width: 10; margin-left: 1; }
    #monitor_profiles, #monitor_search { width: 1fr; height: 3; }
    #monitor_profiles > SelectCurrent {
        border: round $foreground-muted; background: $panel;
    }
    #monitor_profiles:focus > SelectCurrent { border: round $accent; }
    MonitorPane .monitor_table, MonitorPane .monitor_detail {
        height: 1fr; margin: 0 1; border: solid $foreground-muted;
    }
    MonitorPane .monitor_empty {
        height: 1fr; padding: 1 2; color: $foreground-muted;
    }
    MonitorPane .monitor_detail { padding: 0 1; }
    #monitor_hooks { scrollbar-gutter: stable; }
    #monitor_status { height: auto; margin: 0 1; color: $foreground-muted; }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.profiles = []
        self.session = None
        self.revision = 0
        self.session_number = 0
        self.statuses = {}
        self.events = deque(maxlen=MAX_EVENTS)
        self.inbox = deque()
        self.lock = threading.Lock()
        self.rpc_lock = threading.Lock()
        self.lost = self.evicted = 0
        self.inbound_lost = 0
        self.pending_status = None
        self.dirty = False
        self.selected = None
        self.last_connection = None
        self.event_query = None
        self.status_text = ""
        self._hooks_layout_width = 0

    def compose(self):
        with TabbedContent(id="monitor_views", initial="monitor_events_view"):
            with TabPane("Events", id="monitor_events_view"):
                with Horizontal(classes="monitor_controls"):
                    yield Input(placeholder="Search Monitor events", id="monitor_search")
                    yield Button("Clear events", id="monitor_clear")
                yield Label("", id="monitor_status", markup=False)
                yield Label("", id="monitor_events_empty", classes="monitor_empty")
                yield DataTable(id="monitor_events", cursor_type="row", classes="monitor_table")
                with VerticalScroll(id="monitor_detail", classes="monitor_detail"):
                    yield Static(id="monitor_event_text", markup=False)
            with TabPane("Profiles", id="monitor_profiles_view"):
                with Horizontal(classes="monitor_controls"):
                    yield Select([], prompt="Profile", id="monitor_profiles")
                    yield Button("Enable", id="monitor_toggle")
                    yield Button("New profile", id="monitor_new")
                    yield Button("Rename", id="monitor_rename")
                    yield Button("Delete profile", id="monitor_delete")
                with Horizontal(classes="monitor_controls"):
                    yield Button("Add hook", id="monitor_add")
                    yield Button("Edit hook", id="monitor_edit")
                    yield Button("Remove hook", id="monitor_remove")
                    yield Button("Retry hooks", id="monitor_retry")
                    yield Button("Details", id="monitor_hook_details")
                yield Label("", id="monitor_hooks_empty", classes="monitor_empty")
                yield DataTable(id="monitor_hooks", cursor_type="row", classes="monitor_table")

    def on_mount(self):
        self.profiles, warning = load_profiles(self.app.db.get_info("monitor_profiles"))
        if warning:
            self.app.notify(warning, severity="warning")
        events = self.query_one("#monitor_events", DataTable)
        for label, width in (("Time", 12), ("Profile", 16), ("Method", 21), ("Outcome", 10)):
            events.add_column(label, width=width)
        self.refresh_profiles()
        self.refresh_events()
        self.set_interval(0.2, self.drain)

    def on_resize(self):
        if self.is_mounted and self.size.width != self._hooks_layout_width:
            self.refresh_hooks()

    def profile(self):
        value = self.query_one("#monitor_profiles", Select).value
        return next((p for p in self.profiles if p["id"] == value), None)

    def refresh_profiles(self, selected=None):
        select = self.query_one("#monitor_profiles", Select)
        current = selected or select.value
        select.set_options([(Text(p["name"] + (" · enabled" if p["enabled"] else "")), p["id"]) for p in self.profiles])
        ids = [p["id"] for p in self.profiles]
        if ids:
            select.value = current if current in ids else ids[0]
        self.refresh_hooks()

    def refresh_hooks(self):
        table = self.query_one("#monitor_hooks", DataTable)
        previous = table.cursor_row
        width = self.size.width
        resize_columns = not table.columns or width != self._hooks_layout_width
        table.clear(columns=resize_columns)
        if resize_columns:
            available = width - table.styles.margin.width - table.styles.gutter.width
            available -= table.scrollbar_size_vertical + 4 * table.cell_padding
            table.add_column("State", width=self.HOOK_STATE_WIDTH)
            table.add_column("Method overload", width=max(15, available - self.HOOK_STATE_WIDTH))
            self._hooks_layout_width = width
        p = self.profile()
        if p:
            for i, h in enumerate(p["hooks"]):
                state, _ = self.hook_status(p, i)
                table.add_row(state, Text(signature(h), no_wrap=True, overflow="ellipsis"), key=str(i))
        if table.row_count:
            table.move_cursor(row=min(previous, table.row_count - 1))
        table.display = bool(table.row_count)
        empty = self.query_one("#monitor_hooks_empty", Label)
        empty.display = not table.row_count
        empty.update("No hooks yet. Select Add hook to configure a method." if p else "No profiles. Select New profile to get started.")
        self.refresh_controls()

    def hook_status(self, profile, row):
        if not profile["enabled"]:
            return "Disabled", ""
        if self.session is None or self.session is not self.app.frida_session:
            return "Not connected", ""
        return self.statuses.get((profile["id"], row), ("Pending", ""))

    def show_hook(self):
        profile = self.profile()
        row = self.query_one("#monitor_hooks", DataTable).cursor_row
        if profile and 0 <= row < len(profile["hooks"]):
            state, reason = self.hook_status(profile, row)
            content = f"{signature(profile['hooks'][row])}\n\n{state}"
            if reason:
                content += f"\n{reason}"
            self.app.push_screen(ExtraKeyModal(content, title="Hook details"))

    def refresh_controls(self):
        p = self.profile()
        connecting = self.app._connection_state == "connecting"
        online = self.session is not None and self.session is self.app.frida_session
        self.query_one("#monitor_toggle", Button).label = "Disable" if p and p["enabled"] else "Enable"
        self.query_one("#monitor_new", Button).disabled = connecting
        for key in ("rename", "delete", "toggle", "add"):
            self.query_one(f"#monitor_{key}", Button).disabled = connecting or p is None
        for key in ("edit", "remove"):
            self.query_one(f"#monitor_{key}", Button).disabled = connecting or not (p and p["hooks"])
        self.query_one("#monitor_retry", Button).disabled = connecting or not (online and p and p["enabled"] and p["hooks"])
        self.query_one("#monitor_hook_details", Button).disabled = not (p and p["hooks"])

    def save(self, profiles, selected=None):
        try:
            profiles = validate_profiles(profiles)
            self.app.db.set_info("monitor_profiles", json.dumps(profiles))
        except (ValueError, OSError, sqlite3.Error) as exc:
            self.app.notify(str(exc), severity="error")
            return
        self.profiles = profiles
        self.refresh_profiles(selected)
        self.apply_configuration()

    def begin_session(self, session):
        with self.lock:
            self.inbox.clear()
            self.pending_status = None
            self.session = session
        self.session_number += 1
        self.revision = 0
        self.statuses.clear()
        session.monitor_hooks = enabled_hooks(self.profiles)
        session.monitor_cb = lambda payload: self.receive(session, payload)
        self.refresh_hooks()

    def receive(self, session, payload):
        with self.lock:
            if session is not self.session:
                return
            if payload.get("noxenEvent") == "monitor_status":
                self.pending_status = payload
                return
            if len(self.inbox) >= 128:
                self.inbound_lost += len(payload.get("events", [])) + payload.get("dropped", 0)
                return
            self.inbox.append(payload)

    def apply_configuration(self):
        self.revision += 1
        self.statuses.clear()
        self.refresh_hooks()
        if self.session is self.app.frida_session and self.session is not None:
            self.configure_worker(self.session, enabled_hooks(self.profiles), self.revision)

    @work(thread=True)
    def configure_worker(self, session, hooks, revision):
        with self.rpc_lock:
            if session is not self.session or revision != self.revision:
                return
            try:
                session.configure_monitor(hooks, revision)
            except Exception as exc:
                self.receive(session, {"noxenEvent": "monitor_status", "revision": revision,
                    "statuses": [{"profile": h["profile"], "index": h["index"],
                                  "state": "Error", "detail": str(exc)} for h in hooks]})

    def drain(self):
        connection = getattr(self.app, "_connection_state", "disconnected")
        if self.last_connection != connection:
            self.last_connection = connection
            self.refresh_hooks()
        with self.lock:
            messages = list(self.inbox)
            self.inbox.clear()
            self.lost += self.inbound_lost
            self.inbound_lost = 0
            if self.pending_status is not None:
                messages.append(self.pending_status)
                self.pending_status = None
        changed = False
        for payload in messages:
            if payload.get("noxenEvent") == "monitor_status":
                if payload.get("revision") == self.revision:
                    self.statuses = {(s["profile"], s["index"]): (s["state"], s["detail"]) for s in payload["statuses"]}
                    self.refresh_hooks()
            else:
                self.lost += payload.get("dropped", 0)
                for e in payload.get("events", []):
                    self.evicted += len(self.events) == MAX_EVENTS
                    e = dict(e, session=self.session_number)
                    self.events.append(e)
                    changed = True
        self.dirty |= changed
        if (
            self.dirty
            and self.app.query_one("#main_tabs", TabbedContent).active == "tab_monitor"
            and self.query_one("#monitor_views", TabbedContent).active == "monitor_events_view"
        ):
            self.refresh_events()
        self.refresh_event_status()

    def refresh_event_status(self):
        status = f"{len(self.events)} events"
        if self.lost:
            status += f" · {self.lost} lost"
        if self.evicted:
            status += f" · {self.evicted} older events discarded"
        shown = self.query_one("#monitor_events", DataTable).row_count
        if shown < len(self.events):
            status += f" · {shown} shown"
        if status != self.status_text:
            self.query_one("#monitor_status", Label).update(status)
            self.status_text = status

    def refresh_events(self):
        self.dirty = False
        table = self.query_one("#monitor_events", DataTable)
        old = self.selected
        query = self.query_one("#monitor_search", Input).value.casefold()
        matches = [e for e in self.events if not query or query in json.dumps(e, ensure_ascii=True).casefold()]
        visible = {self.event_key(e): e for e in matches[-200:]}
        if self.event_query != query:
            table.clear()
            self.event_query = query
        for row in list(table.rows):
            if row.value not in visible:
                table.remove_row(row)
        for key, e in visible.items():
            if key in table.rows:
                continue
            timestamp = datetime.fromtimestamp(e.get("time", 0) / 1000).strftime("%H:%M:%S.%f")[:-3]
            table.add_row(timestamp, Text(", ".join(e.get("profiles", [])), no_wrap=True, overflow="ellipsis"),
                          Text(e.get("method", "Capture error"), no_wrap=True, overflow="ellipsis"),
                          e.get("outcome", "unknown"), key=key)
        table.display = self.query_one("#monitor_detail").display = bool(visible)
        empty = self.query_one("#monitor_events_empty", Label)
        empty.display = not visible
        if visible:
            key = old if old in visible else next(reversed(visible))
            table.move_cursor(row=table.get_row_index(key), scroll=key != old)
            self.show_event(key)
        else:
            self.selected = None
            self.query_one("#monitor_event_text", Static).update("")
            empty.update("No matching events." if self.events else
                         "No events yet. Enable a profile in Profiles and use the target app.")
        self.query_one("#monitor_clear", Button).disabled = not self.events
        self.refresh_event_status()

    @staticmethod
    def event_key(event):
        return f"{event['session']}:{event['id']}"

    def show_event(self, key):
        if key == self.selected:
            return
        self.selected = key
        event = next((e for e in self.events if self.event_key(e) == key), None)
        if event:
            self.query_one("#monitor_event_text", Static).update(Text(event_detail(event), overflow="fold"))
            self.query_one("#monitor_detail").scroll_home(animate=False, immediate=True)

    def on_data_table_row_highlighted(self, event):
        event.stop()
        table = event.data_table
        if event.cursor_row != table.cursor_row or not table.row_count:
            return
        if table.id == "monitor_events":
            key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            if event.row_key == key:
                self.show_event(key.value)

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated):
        event.stop()
        if event.pane.id == "monitor_events_view" and self.dirty:
            self.refresh_events()

    def on_select_changed(self, event):
        event.stop()
        if event.value == event.select.value:
            self.refresh_hooks()

    def on_input_changed(self, event):
        event.stop()
        if event.input.id == "monitor_search":
            self.refresh_events()

    def on_button_pressed(self, event):
        event.stop()
        action = event.button.id.removeprefix("monitor_")
        p = self.profile()
        if action == "hook_details":
            self.show_hook()
            return
        if action == "clear":
            with self.lock:
                self.inbox.clear()
            self.events.clear()
            self.refresh_events()
            return
        if self.app._connection_state == "connecting":
            return
        if action == "new":
            def add(name):
                if name is not None:
                    new = new_profile(name)
                    self.save(self.profiles + [new], new["id"])
            self.app.push_screen(MonitorDialog(name=""), add)
            return
        if not p:
            return
        profiles = copy.deepcopy(self.profiles)
        target = next(x for x in profiles if x["id"] == p["id"])
        if action == "rename":
            def rename(name):
                if name is not None:
                    target["name"] = name
                    self.save(profiles)
            self.app.push_screen(MonitorDialog(name=p["name"]), rename)
        elif action == "delete":
            self.save([x for x in profiles if x["id"] != p["id"]])
        elif action == "toggle":
            target["enabled"] = not target["enabled"]
            self.save(profiles)
        elif action == "retry":
            self.apply_configuration()
        elif action in ("add", "edit", "remove"):
            row = self.query_one("#monitor_hooks", DataTable).cursor_row
            if action != "add" and not 0 <= row < len(target["hooks"]):
                return
            if action == "remove":
                target["hooks"].pop(row)
                self.save(profiles)
                return
            def save_hook(h):
                if h is not None:
                    if action == "add":
                        target["hooks"].append(h)
                    else:
                        target["hooks"][row] = h
                    self.save(profiles)
            self.app.push_screen(MonitorDialog(hook=None if action == "add" else target["hooks"][row]), save_hook)
