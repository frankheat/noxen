"""Monitor UI and bounded delivery; no Frida calls on the UI thread."""
import asyncio
import copy
import json
import sqlite3
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from itertools import islice
from time import monotonic
from uuid import uuid4

from rich.cells import cell_len
from rich.text import Text
from textual import work
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Input, Label, OptionList, Static, TabbedContent, TabPane
from textual.widgets.option_list import Option

from noxen.modals import ExtraKeyModal
from noxen.monitor import (PROFILE_FORMAT_VERSION, default_profiles, enabled_hooks, event_detail, load_profiles,
                           missing_default_hooks, new_profile, signature, validate_hook, validate_profiles)

ALL_HOOKS_ROW = ":all"


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


class RestoreHooksDialog(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Cancel")]
    DEFAULT_CSS = """
    RestoreHooksDialog { align: center middle; }
    #monitor_restore_dialog {
        width: 85%; max-width: 72; height: auto; padding: 1 2;
        background: $surface; border: solid $foreground-muted;
    }
    #monitor_restore_title { text-style: bold; }
    #monitor_restore_message { height: auto; margin: 1 0; }
    #monitor_restore_dialog Horizontal { height: 3; align: right middle; }
    #monitor_restore_dialog Button { width: auto; min-width: 12; margin-left: 1; }
    """

    def __init__(self, name, count):
        super().__init__()
        self.name_to_restore = name
        self.count = count

    def compose(self):
        hooks = "hook" if self.count == 1 else "hooks"
        with Vertical(id="monitor_restore_dialog"):
            yield Label("Restore missing hooks", id="monitor_restore_title")
            yield Label(f"Add {self.count} missing default {hooks} to {self.name_to_restore}?",
                        id="monitor_restore_message", markup=False)
            with Horizontal():
                yield Button("Cancel", id="monitor_restore_cancel")
                yield Button("Restore", id="monitor_restore_confirm")

    def on_mount(self):
        self.query_one("#monitor_restore_cancel", Button).focus()

    def on_button_pressed(self, event):
        event.stop()
        self.dismiss(event.button.id == "monitor_restore_confirm")


class RecordingDialog(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Cancel")]
    DEFAULT_CSS = """
    RecordingDialog { align: center middle; }
    #recording_dialog { width: 85%; max-width: 72; height: auto; padding: 1 2;
        background: $surface; border: solid $foreground-muted; }
    #recording_message { height: auto; margin: 1 0; }
    #recording_dialog Horizontal { height: 3; align: right middle; }
    #recording_dialog Button { width: auto; min-width: 10; margin-left: 1; }
    """

    def __init__(self, message, confirm, cancel="Cancel"):
        super().__init__()
        self.message, self.confirm, self.cancel = message, confirm, cancel

    def compose(self):
        with Vertical(id="recording_dialog"):
            yield Label(self.message, id="recording_message", markup=False)
            with Horizontal():
                yield Button(self.cancel, id="recording_cancel")
                yield Button(self.confirm, id="recording_confirm")

    def on_mount(self):
        self.query_one("#recording_cancel", Button).focus()

    def on_button_pressed(self, event):
        event.stop()
        self.dismiss(event.button.id == "recording_confirm")


@dataclass
class MonitorRecording:
    id: str = field(default_factory=lambda: uuid4().hex)
    started: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    pending: deque = field(default_factory=deque)
    lost: int = 0
    unsaved: int = 0
    interrupted: bool = False
    dirty: bool = True


class MonitorProfileTable(DataTable):
    class ToggleRequested(Message):
        def __init__(self, profile_id):
            super().__init__()
            self.profile_id = profile_id

    def on_click(self, event):
        meta = event.style.meta
        row = meta.get("row", -1)
        if (event.button == 1 and meta.get("column") == 0
                and not meta.get("out_of_bounds") and 0 <= row < self.row_count):
            profile_id = self.ordered_rows[row].key.value
            if profile_id == ALL_HOOKS_ROW:
                return
            event.prevent_default()
            event.stop()
            self.move_cursor(row=row)
            self.post_message(self.ToggleRequested(profile_id))


class MonitorActionsMenu(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Close")]
    WIDTH = 29
    DEFAULT_CSS = """
    MonitorActionsMenu { align: left top; }
    #monitor_actions_menu { height: auto; border: round $foreground-muted; background: $surface; }
    """

    def __init__(self, anchor, actions):
        super().__init__()
        self.anchor = anchor
        self.actions = actions

    def compose(self):
        yield OptionList(*(Option(label, id=key) for key, label in self.actions), id="monitor_actions_menu")

    def on_mount(self):
        menu = self.query_one(OptionList)
        menu.styles.width = self.WIDTH
        menu.styles.offset = (
            max(0, min(self.anchor.x, self.size.width - self.WIDTH)),
            max(0, min(self.anchor.bottom, self.size.height - len(self.actions) - 2)),
        )
        menu.focus()

    def on_option_list_option_selected(self, event):
        event.stop()
        self.dismiss(event.option_id)

    def on_click(self, event):
        if not self.query_one(OptionList).region.contains(event.screen_x, event.screen_y):
            event.stop()
            self.dismiss()


class MonitorPane(Vertical):
    HOOK_STATE_WIDTH = 13
    PROFILE_LIST_WIDTH = 29
    RECORDING_BATCH = 512
    RECORDING_BUFFER = 4096
    EVENT_PAGE_SIZE = 200

    DEFAULT_CSS = """
    MonitorPane { height: 1fr; }
    MonitorPane .monitor_controls { height: 3; padding: 0 1; align: left middle; background: $panel; }
    MonitorPane .monitor_controls Button { width: auto; min-width: 10; margin-left: 1; }
    #monitor_search { width: 1fr; height: 3; }
    MonitorPane .monitor_table, MonitorPane .monitor_detail {
        height: 1fr; margin: 0 1; border: solid $foreground-muted;
    }
    MonitorPane .monitor_empty {
        height: 1fr; padding: 1 2; color: $foreground-muted;
    }
    MonitorPane .monitor_detail { padding: 0 1; }
    #monitor_profile_body { height: 1fr; padding: 0 1; background: $background; }
    MonitorPane .monitor_profile_panel {
        height: 1fr; border: solid $foreground-muted; border-title-color: $foreground;
    }
    #monitor_profile_panel { margin-right: 1; }
    #monitor_hook_panel { width: 1fr; }
    MonitorPane .monitor_profile_panel .monitor_controls {
        margin-bottom: 1;
    }
    MonitorPane .monitor_profile_panel .monitor_table {
        width: 1fr; margin: 0; border: none; scrollbar-gutter: stable;
    }
    #monitor_hook_actions { height: auto; }
    #monitor_hook_actions.stacked { layout: vertical; }
    #monitor_hook_actions > Horizontal { width: auto; height: 3; }
    #monitor_hook_actions Button { min-width: 0; padding: 0; }
    #monitor_profile_actions { width: 5; min-width: 5; padding: 0; }
    #monitor_status { height: auto; margin: 0 1; color: $foreground-muted; }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.profiles = []
        self.selected_profile = None
        self.hook_rows = []
        self.hook_sorts = {}
        self.session = None
        self.session_was_current = False
        self.revision = 0
        self.session_number = 0
        self.statuses = {}
        self.events = []
        self.inbox = deque()
        self.lock = threading.Lock()
        self.rpc_lock = threading.Lock()
        self.saved_count = self.lost = self.saved_unsaved = self.interrupted_recordings = 0
        self.inbound_lost = 0
        self.pending_status = None
        self.dirty = False
        self.selected = None
        self.last_connection = None
        self.event_query = None
        self.status_text = ""
        self._hooks_layout_width = 0
        self.recording = None
        self.recording_error = ""
        self.retry_recording_at = 0.0
        self.recording_task = None
        self.recording_lock = asyncio.Lock()
        self.clearing = False
        self.finishing = False
        self.stopped_session = None
        self.target = ""
        self.event_pages = []
        self.event_page_task = None
        self.event_page_version = 0
        self.older_event_id = None

    def compose(self):
        with TabbedContent(id="monitor_views", initial="monitor_events_view"):
            with TabPane("Events", id="monitor_events_view"):
                with Horizontal(classes="monitor_controls"):
                    yield Input(placeholder="Search Monitor events", id="monitor_search")
                    yield Button("Newer", id="monitor_newer", disabled=True)
                    yield Button("Older", id="monitor_older", disabled=True)
                    yield Button("Clear events", id="monitor_clear")
                yield Label("", id="monitor_status", markup=False)
                yield Label("", id="monitor_events_empty", classes="monitor_empty")
                yield DataTable(id="monitor_events", cursor_type="row", classes="monitor_table")
                with VerticalScroll(id="monitor_detail", classes="monitor_detail"):
                    yield Static(id="monitor_event_text", markup=False)
            with TabPane("Profiles", id="monitor_profiles_view"):
                with Horizontal(id="monitor_profile_body"):
                    with Vertical(id="monitor_profile_panel", classes="monitor_profile_panel") as profiles:
                        profiles.border_title = "Profiles"
                        with Horizontal(id="monitor_profile_actions_group", classes="monitor_controls"):
                            yield Button("+ New profile", id="monitor_new")
                            yield Button("⋯", id="monitor_profile_actions", tooltip="Profile actions")
                        yield MonitorProfileTable(id="monitor_profiles", cursor_type="row", fixed_rows=1,
                                                  classes="monitor_table")
                    with Vertical(id="monitor_hook_panel", classes="monitor_profile_panel") as hooks:
                        hooks.border_title = "Hooks"
                        with Horizontal(id="monitor_hook_actions", classes="monitor_controls"):
                            with Horizontal():
                                yield Button("+ Add", id="monitor_add")
                                yield Button("Edit", id="monitor_edit")
                                yield Button("Remove", id="monitor_remove")
                                yield Button("Details", id="monitor_hook_details")
                            with Horizontal(id="monitor_hook_restore_group"):
                                yield Button("Restore missing hooks", id="monitor_restore")
                        yield Label("", id="monitor_hooks_empty", classes="monitor_empty")
                        yield DataTable(id="monitor_hooks", cursor_type="row", classes="monitor_table")

    def on_mount(self):
        self.saved_count, self.lost, self.saved_unsaved, self.interrupted_recordings = self.app.db.monitor_event_summary()
        self.profiles, warning = load_profiles(self.app.db.get_info("monitor_profiles"))
        if warning:
            self.app.notify(warning, severity="warning")
        events = self.query_one("#monitor_events", DataTable)
        for label, width in (("Time", 19), ("Profile", 16), ("Method", 21), ("Outcome", 10)):
            events.add_column(label, width=width)
        profiles = self.query_one("#monitor_profiles", DataTable)
        self.query_one("#monitor_profile_panel").styles.width = self.PROFILE_LIST_WIDTH
        profiles.add_column("On", width=2)
        profiles.add_column("Profile", width=17)
        profiles.tooltip = "Click the On column or press Space to toggle a profile."
        self.refresh_profiles()
        self.refresh_events()
        self.dirty = True
        self.set_interval(0.2, self.drain)

    def on_resize(self):
        if self.is_mounted and self.size.width != self._hooks_layout_width:
            self.refresh_hooks()

    def profile(self):
        return next((p for p in self.profiles if p["id"] == self.selected_profile), None)

    def refresh_profiles(self, selected=None):
        table = self.query_one("#monitor_profiles", DataTable)
        current = selected or self.selected_profile
        previous_row = table.cursor_row
        table.clear()
        table.add_row("", "All hooks", key=ALL_HOOKS_ROW)
        for profile in self.profiles:
            table.add_row("✓" if profile["enabled"] else "–",
                          Text(profile["name"], no_wrap=True, overflow="ellipsis"), key=profile["id"])
        if current is None and self.profiles:
            current = self.profiles[0]["id"]
        row = table.get_row_index(current) if current in table.rows else min(previous_row, table.row_count - 1)
        table.move_cursor(row=row, scroll=self.selected_profile is not None)
        current = table.ordered_rows[row].key.value
        changed = current != self.selected_profile
        self.selected_profile = current
        self.refresh_hooks(reset_selection=changed)

    def refresh_hooks(self, reset_selection=False, rebuild_columns=False):
        table = self.query_one("#monitor_hooks", DataTable)
        all_hooks = self.selected_profile == ALL_HOOKS_ROW
        previous = 0 if reset_selection else table.cursor_row
        selected_key = None
        if not reset_selection and 0 <= previous < table.row_count:
            selected_key = table.ordered_rows[previous].key
        width = self.size.width
        profile = self.profile()
        profiles = self.profiles if all_hooks else [profile] if profile else []
        self.hook_rows = [(p, i) for p in profiles for i in range(len(p["hooks"]))]
        sort_column, reverse = self.hook_sorts.get(self.selected_profile, (None, False))
        if sort_column == "state":
            self.hook_rows.sort(key=lambda row: self.hook_status(*row)[0].casefold(), reverse=reverse)
        elif sort_column == "profile":
            self.hook_rows.sort(key=lambda row: row[0]["name"].casefold(), reverse=reverse)
        elif sort_column == "method":
            self.hook_rows.sort(key=lambda row: signature(row[0]["hooks"][row[1]]).casefold(), reverse=reverse)
        signatures = [signature(p["hooks"][i]) for p, i in self.hook_rows]

        available = self.hook_panel_content_width()
        column_count = 3 if all_hooks else 2
        profile_width = min(17, max(10, width // 8)) if all_hooks else 0
        available -= table.scrollbar_size_vertical + column_count * 2 * table.cell_padding
        method_width = max(15, available - self.HOOK_STATE_WIDTH - profile_width)
        if all_hooks:
            method_width = max(method_width, max(map(cell_len, signatures), default=0))
        method_column = table.columns.get("method")
        resize_columns = (
            rebuild_columns or reset_selection or len(table.columns) != column_count or width != self._hooks_layout_width
            or method_column is None or method_column.width != method_width
        )
        table.clear(columns=resize_columns)
        if resize_columns:
            columns = [("state", "State", self.HOOK_STATE_WIDTH)]
            if all_hooks:
                columns.append(("profile", "Profile", profile_width))
            columns.append(("method", "Method overload", method_width))
            for key, label, column_width in columns:
                if key == sort_column:
                    label += " ↓" if reverse else " ↑"
                table.add_column(label, width=column_width, key=key)
            self._hooks_layout_width = width
        for (p, i), method in zip(self.hook_rows, signatures):
            state, _ = self.hook_status(p, i)
            cells = [state]
            if all_hooks:
                cells.append(Text(p["name"], no_wrap=True, overflow="ellipsis"))
            cells.append(Text(method, no_wrap=True, overflow="ellipsis"))
            table.add_row(*cells, key=f"{p['id']}:{method}")
        if table.row_count:
            row = table.get_row_index(selected_key) if selected_key in table.rows else min(previous, table.row_count - 1)
            table.move_cursor(row=row)
        table.display = bool(table.row_count)
        empty = self.query_one("#monitor_hooks_empty", Label)
        empty.display = not table.row_count
        if all_hooks and self.profiles:
            empty.update("No hooks yet. Select a profile to add a hook.")
        else:
            empty.update("No hooks yet. Select Add hook to configure a method." if profile else
                         "No profiles. Select New profile to get started.")
        self.refresh_controls()

    def hook_panel_content_width(self):
        body = self.query_one("#monitor_profile_body")
        profiles = self.query_one("#monitor_profile_panel")
        hooks = self.query_one("#monitor_hook_panel")
        return (self.size.width - body.styles.gutter.width - self.PROFILE_LIST_WIDTH
                - profiles.styles.margin.width - hooks.styles.gutter.width)

    def hook_status(self, profile, row):
        if not profile["enabled"]:
            return "Disabled", ""
        if self.session is None or self.session is not self.app.frida_session:
            return "Not connected", ""
        return self.statuses.get((profile["id"], row), ("Pending", ""))

    def show_hook(self):
        row = self.query_one("#monitor_hooks", DataTable).cursor_row
        if 0 <= row < len(self.hook_rows):
            profile, index = self.hook_rows[row]
            state, reason = self.hook_status(profile, index)
            content = f"{signature(profile['hooks'][index])}\n\n{state}"
            if self.selected_profile == ALL_HOOKS_ROW:
                content += f"\nProfile: {profile['name']}"
            if reason:
                content += f"\n{reason}"
            self.app.push_screen(ExtraKeyModal(content, title="Hook details"))

    def refresh_controls(self):
        p = self.profile()
        connecting = self.app._connection_state == "connecting"
        self.query_one("#monitor_new", Button).disabled = connecting
        actions = self.query_one("#monitor_profile_actions", Button)
        actions.display = p is not None or bool(self.missing_profiles())
        actions.disabled = connecting
        add = self.query_one("#monitor_add", Button)
        add.display = p is not None
        add.disabled = connecting
        for key in ("edit", "remove"):
            button = self.query_one(f"#monitor_{key}", Button)
            button.display = p is not None
            button.disabled = connecting or not (p and p["hooks"])
        self.query_one("#monitor_hook_details", Button).disabled = not self.hook_rows
        restore = self.query_one("#monitor_restore", Button)
        missing = len(missing_default_hooks(p))
        restore.display = self.query_one("#monitor_hook_restore_group").display = bool(missing)
        restore.disabled = connecting
        toolbar = self.query_one("#monitor_hook_actions")
        if missing:
            restore.label = f"Restore missing hooks ({missing})"
        required = toolbar.styles.gutter.width + sum(
            button.get_content_width(self.size, self.app.size) + button.styles.gutter.width + button.styles.margin.width
            for button in toolbar.query(Button) if button.display
        )
        toolbar.set_class(bool(missing) and required > self.hook_panel_content_width(), "stacked")

    def missing_profiles(self):
        existing = {profile["id"] for profile in self.profiles}
        return [profile for profile in default_profiles() if profile["id"] not in existing]

    def show_profile_actions(self, profile, anchor):
        actions = []
        profile_id = None
        if profile is not None:
            profile_id = profile["id"]
            actions.extend([
                ("toggle", "Disable" if profile["enabled"] else "Enable"),
                ("rename", "Rename"),
                ("delete", "Delete profile"),
            ])
            online = self.session is not None and self.session is self.app.frida_session
            if online and profile["enabled"] and profile["hooks"]:
                actions.append(("retry", "Retry hooks"))
        missing = len(self.missing_profiles())
        if missing:
            actions.append(("restore_profiles", f"Restore profiles ({missing})"))
        if actions:
            self.app.push_screen(MonitorActionsMenu(anchor, actions),
                                 lambda action: self.run_profile_action(profile_id, action, anchor))

    def run_profile_action(self, profile_id, action, anchor):
        if action is None or self.app._connection_state == "connecting":
            return
        if action == "restore_profiles":
            choices = [(p["id"], p["name"]) for p in self.missing_profiles()]
            if choices:
                self.app.push_screen(MonitorActionsMenu(anchor, choices), self.restore_profile)
            return
        profiles = copy.deepcopy(self.profiles)
        profile = next((p for p in profiles if p["id"] == profile_id), None)
        if profile is None:
            return
        if action == "toggle":
            self.toggle_profile(profile_id)
        elif action == "rename":
            def rename(name):
                if name is not None:
                    profile["name"] = name
                    self.save(profiles, profile_id)
            self.app.push_screen(MonitorDialog(name=profile["name"]), rename)
        elif action == "delete":
            self.save([p for p in profiles if p["id"] != profile_id])
        elif action == "retry":
            self.apply_configuration()

    def restore_profile(self, profile_id):
        if profile_id is None or self.app._connection_state == "connecting":
            return
        profile = next((p for p in self.missing_profiles() if p["id"] == profile_id), None)
        if profile is None:
            return
        if any(p["name"].casefold() == profile["name"].casefold() for p in self.profiles):
            self.app.notify(f"Rename the existing {profile['name']} profile before restoring the default.",
                            severity="error", markup=False)
            return
        self.save([*self.profiles, profile], profile_id)

    def save(self, profiles, selected=None):
        try:
            profiles = validate_profiles(profiles)
            self.app.db.set_info("monitor_profiles", json.dumps({"version": PROFILE_FORMAT_VERSION, "profiles": profiles}))
        except (ValueError, OSError, sqlite3.Error) as exc:
            self.app.notify(str(exc), severity="error")
            return
        self.profiles = profiles
        self.refresh_profiles(selected)
        self.apply_configuration()

    def restore_hooks(self, profile):
        missing = missing_default_hooks(profile)
        if not missing:
            return
        profile_id = profile["id"]

        def restore(confirmed):
            if not confirmed or self.app._connection_state == "connecting":
                return
            profiles = copy.deepcopy(self.profiles)
            target = next((p for p in profiles if p["id"] == profile_id), None)
            additions = missing_default_hooks(target)
            if additions:
                target["hooks"].extend(additions)
                self.save(profiles, profile_id)

        self.app.push_screen(RestoreHooksDialog(profile["name"], len(missing)), restore)

    def begin_session(self, session, target=""):
        self.drain()
        with self.lock:
            self.inbox.clear()
            self.pending_status = None
            self.session = session
            self.session_was_current = session is self.app.frida_session
        self.session_number += 1
        self.target = target
        self.stopped_session = None
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
        if self.clearing:
            return
        connection = getattr(self.app, "_connection_state", "disconnected")
        if self.last_connection != connection:
            self.last_connection = connection
            self.refresh_hooks()
        with self.lock:
            disconnected = (
                self.session_was_current and self.session is not None
                and self.session is not self.app.frida_session
            )
            interrupted = disconnected and self.stopped_session is not self.session
            if disconnected:
                self.session = None
            messages = list(self.inbox)
            self.inbox.clear()
            lost = self.inbound_lost
            self.inbound_lost = 0
            if self.pending_status is not None:
                messages.append(self.pending_status)
                self.pending_status = None
        captured = []
        for payload in messages:
            if payload.get("noxenEvent") == "monitor_status":
                if payload.get("revision") == self.revision:
                    self.statuses = {(s["profile"], s["index"]): (s["state"], s["detail"]) for s in payload["statuses"]}
                    self.refresh_hooks()
            else:
                lost += payload.get("dropped", 0)
                for event in payload.get("events", []):
                    event = dict(event, session=self.session_number)
                    if self.target:
                        event["target"] = self.target
                    captured.append(event)
        self.lost += lost
        self.queue_recording(captured, lost)
        if interrupted and self.recording:
            self.recording.interrupted = True
        self.refresh_page_if_visible()
        self.refresh_event_status()

    def queue_recording(self, events, lost):
        if self.recording is None and (events or lost):
            self.recording = MonitorRecording()
        recording = self.recording
        if recording is None:
            return
        if events or lost:
            available = self.RECORDING_BUFFER - len(recording.pending)
            recording.pending.extend(events[:available])
            recording.unsaved += max(0, len(events) - available)
            recording.lost += lost
            recording.dirty = True
            if self.recording_error and not self.event_pages:
                self.dirty = True
        if (
            recording.dirty and self.recording_task is None and not self.finishing
            and monotonic() >= self.retry_recording_at
        ):
            self.recording_task = asyncio.create_task(self.write_recording(recording))

    async def write_recording(self, recording, finish=False):
        try:
            while True:
                batch = list(islice(recording.pending, self.RECORDING_BATCH))
                last_batch = len(batch) == len(recording.pending)
                status = "open"
                if finish and last_batch:
                    status = "incomplete" if recording.interrupted or recording.unsaved else "complete"
                recording.dirty = not last_batch
                await asyncio.to_thread(
                    self.app.db.save_monitor_batch, recording.id, recording.started, batch,
                    recording.lost, recording.unsaved, status,
                )
                for _ in batch:
                    recording.pending.popleft()
                self.saved_count += len(batch)
                self.recording_error = ""
                self.retry_recording_at = 0.0
                if not self.event_pages:
                    self.dirty = True
                if not finish or not recording.dirty:
                    return True
        except (ValueError, OSError, sqlite3.Error) as exc:
            recording.dirty = True
            if not self.recording_error:
                self.app.notify(str(exc), title="Could not save Monitor events", severity="error", markup=False)
            self.recording_error = str(exc)
            self.retry_recording_at = monotonic() + 2.0
            if not self.event_pages:
                self.dirty = True
            return False
        finally:
            if not finish:
                self.recording_task = None
            self.refresh_event_status()

    async def finish_recording(self):
        self.finishing = True
        self.drain()
        recording = self.recording
        if recording is None:
            return True
        if self.recording_task is not None:
            await self.recording_task
        if not await self.write_recording(recording, finish=True):
            return False
        self.recording = None
        return True

    async def stop_recording_feed(self, session):
        if session is None or self.stopped_session is session:
            return
        self.drain()
        incomplete = False
        try:
            final = await asyncio.to_thread(session.stop_monitor)
            if final:
                incomplete = final.get("incomplete", False)
                self.receive(session, final)
        except Exception:
            incomplete = True
        self.stopped_session = session
        self.drain()
        if incomplete and self.recording:
            self.recording.interrupted = True

    def request_event_page(self):
        self.event_page_version += 1
        self.older_event_id = None
        self.dirty = True
        self.refresh_page_if_visible()
        self.refresh_event_status()

    def refresh_page_if_visible(self):
        if (
            self.dirty and not self.clearing and not self.finishing and self.event_page_task is None
            and self.app.query_one("#main_tabs", TabbedContent).active == "tab_monitor"
            and self.query_one("#monitor_views", TabbedContent).active == "monitor_events_view"
        ):
            self.dirty = False
            self.event_page_task = asyncio.create_task(self.load_event_page())

    async def load_event_page(self):
        version = self.event_page_version
        before = self.event_pages[-1] if self.event_pages else None
        query = self.query_one("#monitor_search", Input).value.casefold()

        def cancelled():
            return self.clearing or self.finishing or version != self.event_page_version

        try:
            events, has_older = await asyncio.to_thread(
                self.app.db.monitor_event_page, query, before, self.EVENT_PAGE_SIZE, cancelled
            )
            if cancelled():
                return
            visible = events
            if before is None and self.recording_error and self.recording:
                visible_by_key = {self.event_key(event): event for event in events}
                for event in self.recording.pending:
                    if not query or query in json.dumps(event).casefold():
                        pending = dict(event, _recording=self.recording.id)
                        visible_by_key.setdefault(self.event_key(pending), pending)
                visible = list(visible_by_key.values())[-self.EVENT_PAGE_SIZE:]
            oldest_visible = next((event["_db_id"] for event in visible if "_db_id" in event), None)
            self.older_event_id = None
            if events:
                if oldest_visible is None:
                    self.older_event_id = events[-1]["_db_id"] + 1
                elif has_older or oldest_visible > events[0]["_db_id"]:
                    self.older_event_id = oldest_visible
            self.events = visible
            self.refresh_events(query, before)
        except (OSError, sqlite3.Error, ValueError) as exc:
            if not cancelled():
                self.app.notify(str(exc), title="Could not read Monitor events", severity="error", markup=False)
        finally:
            self.event_page_task = None

    @work
    async def clear_events(self):
        if self.clearing:
            return
        async with self.recording_lock:
            self.drain()
            self.clearing = True
            try:
                if self.recording_task is not None:
                    await self.recording_task
                await asyncio.to_thread(self.app.db.clear_monitor_events)
            except (OSError, sqlite3.Error) as exc:
                self.app.notify(str(exc), title="Could not clear Monitor events", severity="error", markup=False)
                return
            finally:
                self.clearing = False
            self.recording = None
            self.recording_error = ""
            self.retry_recording_at = 0.0
            self.saved_count = self.lost = self.saved_unsaved = self.interrupted_recordings = 0
            self.events = []
            self.event_pages.clear()
            self.refresh_events()
            self.request_event_page()

    def refresh_event_status(self):
        status = f"{self.saved_count} saved"
        if self.event_pages:
            status += f" · Page {len(self.event_pages) + 1}"
        if self.lost:
            status += f" · {self.lost} lost during capture"
        unsaved = self.saved_unsaved + (self.recording.unsaved if self.recording else 0)
        if unsaved:
            status += f" · {unsaved} not saved"
        if self.recording_error and self.recording:
            status += f" · Save failed · {len(self.recording.pending)} waiting to save"
        if self.interrupted_recordings:
            status += f" · {self.interrupted_recordings} incomplete captures"
        if status != self.status_text:
            self.query_one("#monitor_status", Label).update(status)
            self.status_text = status
        self.query_one("#monitor_newer", Button).disabled = not self.event_pages
        self.query_one("#monitor_older", Button).disabled = self.older_event_id is None
        self.query_one("#monitor_clear", Button).disabled = not (self.saved_count or self.recording or self.lost)

    def refresh_events(self, query="", before=None):
        table = self.query_one("#monitor_events", DataTable)
        old = self.selected
        visible = {self.event_key(e): e for e in self.events}
        if self.event_query != (query, before):
            table.clear()
            self.event_query = (query, before)
        for row in list(table.rows):
            if row.value not in visible:
                table.remove_row(row)
        for key, e in visible.items():
            if key in table.rows:
                continue
            timestamp = datetime.fromtimestamp(e.get("time", 0) / 1000).strftime("%Y-%m-%d %H:%M:%S")
            method = e.get("method", "Capture error")
            if method == "$init" and e.get("class"):
                method = e["class"].rsplit(".", 1)[-1]
            table.add_row(timestamp, Text(", ".join(e.get("profiles", [])), no_wrap=True, overflow="ellipsis"),
                          Text(method, no_wrap=True, overflow="ellipsis"),
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
            empty.update("No matching events." if query or before is not None else
                         "No events yet. Enable a profile in Profiles and use the target app.")
        self.refresh_event_status()

    @staticmethod
    def event_key(event):
        return f"{event['_recording']}:{event['session']}:{event['id']}"

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
        if table.id not in ("monitor_events", "monitor_profiles"):
            return
        key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        if event.row_key != key:
            return
        if table.id == "monitor_events":
            self.show_event(key.value)
        elif key.value != self.selected_profile:
            self.selected_profile = key.value
            self.refresh_hooks(reset_selection=True)

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected):
        if event.data_table.id != "monitor_hooks":
            return
        event.stop()
        key = event.column_key.value
        previous, reverse = self.hook_sorts.get(self.selected_profile, (None, False))
        self.hook_sorts[self.selected_profile] = (key, key == previous and not reverse)
        self.refresh_hooks(rebuild_columns=True)

    def on_key(self, event):
        if event.key == "space" and getattr(self.app.focused, "id", None) == "monitor_profiles":
            event.stop()
            if self.selected_profile != ALL_HOOKS_ROW:
                self.toggle_profile(self.selected_profile)

    def on_monitor_profile_table_toggle_requested(self, event):
        event.stop()
        self.toggle_profile(event.profile_id)

    def toggle_profile(self, profile_id):
        if self.app._connection_state == "connecting":
            return
        profiles = copy.deepcopy(self.profiles)
        profile = next((p for p in profiles if p["id"] == profile_id), None)
        if profile:
            profile["enabled"] = not profile["enabled"]
            self.save(profiles, profile_id)

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated):
        event.stop()
        if event.pane.id == "monitor_events_view":
            self.refresh_page_if_visible()

    def on_input_changed(self, event):
        event.stop()
        if event.input.id == "monitor_search" and event.value == event.input.value:
            self.event_pages.clear()
            self.request_event_page()

    def on_button_pressed(self, event):
        event.stop()
        action = event.button.id.removeprefix("monitor_")
        if action == "newer" and self.event_pages:
            self.event_pages.pop()
            self.request_event_page()
            return
        if action == "older" and self.older_event_id is not None:
            self.event_pages.append(self.older_event_id)
            self.request_event_page()
            return
        p = self.profile()
        if action == "hook_details":
            self.show_hook()
            return
        if action == "clear":
            self.clear_events()
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
        if action == "profile_actions":
            self.show_profile_actions(p, event.button.region)
            return
        if not p:
            return
        if action == "restore":
            self.restore_hooks(p)
            return
        profiles = copy.deepcopy(self.profiles)
        target = next(x for x in profiles if x["id"] == p["id"])
        if action in ("add", "edit", "remove"):
            row = self.query_one("#monitor_hooks", DataTable).cursor_row
            if action != "add":
                if not 0 <= row < len(self.hook_rows):
                    return
                _, row = self.hook_rows[row]
            if action == "remove":
                target["hooks"].pop(row)
                self.save(profiles, p["id"])
                return
            def save_hook(h):
                if h is not None:
                    if action == "add":
                        target["hooks"].append(h)
                    else:
                        target["hooks"][row] = h
                    self.save(profiles)
            self.app.push_screen(MonitorDialog(hook=None if action == "add" else target["hooks"][row]), save_hook)
