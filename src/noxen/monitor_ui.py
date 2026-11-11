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
from uuid import uuid4

from rich.cells import cell_len
from rich.text import Text
from textual import work
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Input, Label, OptionList, Select, Static, TabbedContent, TabPane
from textual.widgets.option_list import Option

from noxen.modals import ExtraKeyModal
from noxen.monitor import (MAX_EVENTS, PROFILE_FORMAT_VERSION, default_profiles, enabled_hooks, event_detail, load_profiles,
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
    accepting: bool = True
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
    ARCHIVE_PAGE = 200

    DEFAULT_CSS = """
    MonitorPane { height: 1fr; }
    MonitorPane .monitor_controls { height: 3; padding: 0 1; align: left middle; background: $panel; }
    MonitorPane .monitor_controls Button { width: auto; min-width: 10; margin-left: 1; }
    #monitor_search, #monitor_recordings { width: 1fr; height: 3; }
    #monitor_recordings > SelectCurrent {
        border: round $foreground-muted; background: $panel;
    }
    #monitor_recordings:focus > SelectCurrent { border: round $accent; }
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
        self.recording_enabled = False
        self.recording = None
        self.recording_error = ""
        self.recording_task = None
        self.recording_lock = asyncio.Lock()
        self.stopped_session = None
        self.target = ""
        self.saved_recordings = {}
        self.archive = "live"
        self.archive_page = 0
        self.archive_events = []
        self.archive_search_timer = None

    def compose(self):
        with TabbedContent(id="monitor_views", initial="monitor_events_view"):
            with TabPane("Events", id="monitor_events_view"):
                with Horizontal(classes="monitor_controls"):
                    yield Input(placeholder="Search Monitor events", id="monitor_search")
                    yield Button("Clear events", id="monitor_clear")
                with Horizontal(classes="monitor_controls"):
                    yield Select([("Live events", "live")], value="live", allow_blank=False, id="monitor_recordings")
                    yield Button("Record to project", id="monitor_record")
                    yield Button("Retry save", id="monitor_retry_recording")
                    yield Button("Newer", id="monitor_newer")
                    yield Button("Older", id="monitor_older")
                    yield Button("Delete", id="monitor_delete_recording")
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
        self.recording_enabled = self.app.db.get_info("monitor_recording_enabled") == "1"
        self.refresh_recordings()
        self.refresh_recording_controls()
        self.profiles, warning = load_profiles(self.app.db.get_info("monitor_profiles"))
        if warning:
            self.app.notify(warning, severity="warning")
        events = self.query_one("#monitor_events", DataTable)
        for label, width in (("Time", 12), ("Profile", 16), ("Method", 21), ("Outcome", 10)):
            events.add_column(label, width=width)
        profiles = self.query_one("#monitor_profiles", DataTable)
        self.query_one("#monitor_profile_panel").styles.width = self.PROFILE_LIST_WIDTH
        profiles.add_column("On", width=2)
        profiles.add_column("Profile", width=17)
        profiles.tooltip = "Click the On column or press Space to toggle a profile."
        self.refresh_profiles()
        self.refresh_events()
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
                for e in payload.get("events", []):
                    self.evicted += len(self.events) == MAX_EVENTS
                    e = dict(e, session=self.session_number)
                    if self.target:
                        e["target"] = self.target
                    self.events.append(e)
                    captured.append(e)
        self.lost += lost
        self.queue_recording(captured, lost)
        if interrupted and self.recording:
            self.recording.interrupted = True
        self.dirty |= bool(captured)
        if (
            self.dirty
            and self.archive == "live"
            and self.app.query_one("#main_tabs", TabbedContent).active == "tab_monitor"
            and self.query_one("#monitor_views", TabbedContent).active == "monitor_events_view"
        ):
            self.refresh_events()
        self.refresh_event_status()

    def queue_recording(self, events, lost):
        if not self.recording_enabled:
            return
        if self.recording is None and (events or lost):
            self.recording = MonitorRecording()
        recording = self.recording
        if recording is None or not recording.accepting:
            return
        if events or lost:
            available = self.RECORDING_BUFFER - len(recording.pending)
            recording.pending.extend(events[:available])
            recording.unsaved += max(0, len(events) - available)
            recording.lost += lost
            recording.dirty = True
        if recording.dirty and self.recording_task is None and not self.recording_error:
            self.recording_task = asyncio.create_task(self.write_recording(recording))

    async def write_recording(self, recording, finish=False, discard=False):
        try:
            while True:
                batch = [] if discard else list(islice(recording.pending, self.RECORDING_BATCH))
                last_batch = discard or len(batch) == len(recording.pending)
                unsaved = recording.unsaved + (len(recording.pending) if discard else 0)
                status = "open"
                if finish and last_batch:
                    status = "incomplete" if recording.interrupted or unsaved else "complete"
                recording.dirty = not last_batch
                await asyncio.to_thread(
                    self.app.db.save_monitor_batch, recording.id, recording.started, batch,
                    recording.lost, unsaved, status,
                )
                for _ in batch:
                    recording.pending.popleft()
                if not finish or last_batch:
                    return True
        except (ValueError, OSError, sqlite3.Error) as exc:
            recording.dirty = True
            self.recording_error = str(exc)
            self.refresh_recording_controls()
            self.refresh_event_status()
            self.app.notify(self.recording_error, title="Monitor recording paused", severity="error", markup=False)
            return False
        finally:
            if not finish:
                self.recording_task = None

    async def finish_recording(self, discard=False):
        self.drain()
        recording = self.recording
        if recording is None:
            return True
        recording.accepting = False
        if self.recording_task is not None:
            await self.recording_task
        if not await self.write_recording(recording, finish=True, discard=discard):
            recording.accepting = True
            return False
        self.recording = None
        self.recording_error = ""
        self.refresh_recordings()
        self.refresh_recording_controls()
        return True

    async def stop_recording_feed(self, session):
        if not self.recording_enabled or session is None or self.stopped_session is session:
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

    @work
    async def toggle_recording(self, retry=False):
        if self.recording_lock.locked():
            return
        async with self.recording_lock:
            if retry:
                if self.recording_error and self.recording and await self.write_recording(self.recording):
                    self.recording_error = ""
                    self.refresh_recording_controls()
                    self.refresh_event_status()
                return
            enabled = not self.recording_enabled
            if enabled and not await self.app.push_screen_wait(RecordingDialog(
                "Save Monitor events automatically in this project? Arguments and return values may contain sensitive data.",
                "Start recording",
            )):
                return
            if not enabled and not await self.finish_recording():
                discard = await self.app.push_screen_wait(RecordingDialog(
                    f"Monitor recording could not be saved.\n\n{self.recording_error}",
                    "Discard unsaved events",
                ))
                if not discard or not await self.finish_recording(discard=True):
                    return
            if not enabled:
                self.recording_enabled = False
            try:
                await asyncio.to_thread(self.app.db.set_info, "monitor_recording_enabled", "1" if enabled else "0")
            except (OSError, sqlite3.Error) as exc:
                self.recording_enabled = not enabled
                self.app.notify(str(exc), title="Could not save recording setting", severity="error", markup=False)
                return
            self.recording_enabled = enabled
            self.refresh_recording_controls()
            self.refresh_event_status()

    def refresh_recordings(self):
        rows = self.app.db.monitor_recordings()
        self.saved_recordings = {row[0]: row[1:] for row in rows}
        options = [("Live events", "live")]
        for key, started, _, _, status in rows:
            if self.recording and key == self.recording.id:
                continue
            when = datetime.fromisoformat(started).astimezone().strftime("%Y-%m-%d %H:%M:%S")
            label = when if status == "complete" else f"{when} · incomplete"
            options.append((label, key))
        select = self.query_one("#monitor_recordings", Select)
        select.set_options(options)
        select.value = self.archive if self.archive in self.saved_recordings else "live"

    def refresh_recording_controls(self, has_older=False):
        live = self.archive == "live"
        button = self.query_one("#monitor_record", Button)
        button.display = live
        button.label = "Stop recording" if self.recording_enabled else "Record to project"
        self.query_one("#monitor_retry_recording", Button).display = live and bool(self.recording_error)
        for action in ("newer", "older", "delete_recording"):
            self.query_one(f"#monitor_{action}", Button).display = not live
        self.query_one("#monitor_newer", Button).disabled = self.archive_page == 0
        self.query_one("#monitor_older", Button).disabled = not has_older

    @work(exclusive=True, group="monitor_archive")
    async def load_archive(self):
        key, page = self.archive, self.archive_page
        if key == "live":
            return
        query = self.query_one("#monitor_search", Input).value.casefold()
        try:
            events, has_older = await asyncio.to_thread(
                self.app.db.monitor_recording_page, key, query, page * self.ARCHIVE_PAGE, self.ARCHIVE_PAGE,
            )
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.app.notify(str(exc), title="Could not read recording", severity="error", markup=False)
            return
        if (key, page, query) != (
            self.archive, self.archive_page, self.query_one("#monitor_search", Input).value.casefold()
        ):
            return
        self.archive_events = events
        self.refresh_events()
        self.refresh_recording_controls(has_older)

    @work
    async def delete_recording(self, key):
        if not await self.app.push_screen_wait(RecordingDialog(
            "Delete this Monitor recording from the project?", "Delete"
        )):
            return
        try:
            await asyncio.to_thread(self.app.db.delete_monitor_recording, key)
        except (OSError, sqlite3.Error) as exc:
            self.app.notify(str(exc), title="Could not delete recording", severity="error", markup=False)
            return
        self.refresh_recordings()

    def refresh_event_status(self):
        if self.archive != "live":
            _, lost, unsaved, state = self.saved_recordings.get(self.archive, ("", 0, 0, "open"))
            status = f"Page {self.archive_page + 1} · {'Saved' if state == 'complete' else 'Incomplete'}"
            if lost:
                status += f" · {lost} lost during capture"
            if unsaved:
                status += f" · {unsaved} not saved"
            if status != self.status_text:
                self.query_one("#monitor_status", Label).update(status)
                self.status_text = status
            return
        status = f"{len(self.events)} events"
        if self.lost:
            status += f" · {self.lost} lost"
        if self.evicted:
            status += f" · {self.evicted} older events discarded"
        shown = self.query_one("#monitor_events", DataTable).row_count
        if shown < len(self.events):
            status += f" · {shown} shown"
        if self.recording_error:
            status += " · Recording paused"
        elif self.recording_enabled:
            status += " · Recording to project"
        if self.recording and self.recording.unsaved:
            status += f" · {self.recording.unsaved} not saved"
        if status != self.status_text:
            self.query_one("#monitor_status", Label).update(status)
            self.status_text = status

    def refresh_events(self):
        self.dirty = False
        table = self.query_one("#monitor_events", DataTable)
        old = self.selected
        query = self.query_one("#monitor_search", Input).value.casefold()
        matches = self.archive_events if self.archive != "live" else [
            e for e in self.events if not query or query in json.dumps(e, ensure_ascii=True).casefold()
        ]
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
            empty.update("No matching events." if self.events or self.archive != "live" else
                         "No events yet. Enable a profile in Profiles and use the target app.")
        self.query_one("#monitor_clear", Button).disabled = self.archive != "live" or not self.events
        self.refresh_event_status()

    @staticmethod
    def event_key(event):
        return f"{event['session']}:{event['id']}"

    def show_event(self, key):
        if key == self.selected:
            return
        self.selected = key
        events = self.events if self.archive == "live" else self.archive_events
        event = next((e for e in events if self.event_key(e) == key), None)
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
        if event.pane.id == "monitor_events_view" and self.dirty and self.archive == "live":
            self.refresh_events()

    def on_select_changed(self, event):
        event.stop()
        if event.value != event.select.value:
            return
        if event.select.id == "monitor_recordings":
            if event.value == self.archive:
                return
            self.archive = event.value
            self.archive_page = 0
            self.archive_events = []
            self.selected = None
            self.query_one("#monitor_events", DataTable).clear()
            self.refresh_recording_controls()
            self.refresh_events()
            self.load_archive()

    def on_input_changed(self, event):
        event.stop()
        if event.input.id == "monitor_search":
            if self.archive == "live":
                self.refresh_events()
            else:
                self.archive_page = 0
                self.refresh_recording_controls()
                if self.archive_search_timer is not None:
                    self.archive_search_timer.stop()
                self.archive_search_timer = self.set_timer(0.15, self.load_archive)

    def on_button_pressed(self, event):
        event.stop()
        action = event.button.id.removeprefix("monitor_")
        if action == "record":
            self.toggle_recording()
            return
        if action == "retry_recording":
            self.toggle_recording(retry=True)
            return
        if action in ("newer", "older"):
            self.archive_page += 1 if action == "older" else -1
            self.refresh_recording_controls()
            self.load_archive()
            return
        if action == "delete_recording":
            self.delete_recording(self.archive)
            return
        p = self.profile()
        if action == "hook_details":
            self.show_hook()
            return
        if action == "clear":
            self.drain()
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
