"""Sender requests and execution records. UI and MCP share SenderService."""

import copy
import json
import sqlite3
from uuid import uuid4

from rich.text import Text
from textual import work
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Label, RichLog, Rule, Select, TabbedContent, TabPane, TextArea

from noxen.modals import ModalButton, ColumnSelectModal
from noxen.monitor_ui import RecordingDialog
from noxen.history_columns import normalize_column_widths
from noxen.sender import OPERATIONS, INTENT_OPERATIONS, empty_request, render_sender_detail, compare_sender_runs
from noxen.exporting import write_sender_export
from noxen.sender_capture import prepare_intent_request
from noxen.sender_service import endpoint_for_app, sender_io
from noxen.textual_compat import is_select_empty
from noxen.sender_editor import MISSING, ScalarField, OptionalSection, object_fields, object_sections, changing_draft, check_draft_ready

SENDER_COLUMNS = {
    "sender_requests": [("name", "Name"), ("operation", "Operation"), ("revision", "Revision")],
    "sender_runs": [("id", "ID"), ("name", "Request"), ("state", "State"), ("sender", "Sender"), ("createdAt", "Time")],
}
class SenderCompareModal(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Close")]
    DEFAULT_CSS = """
    SenderCompareModal { align: center middle; }
    SenderCompareModal > Vertical { width: 90%; height: 85%; padding: 1 2; border: solid $foreground-muted; background: $surface; }
    SenderCompareModal Label { margin-bottom: 1; }
    SenderCompareModal Horizontal { height: 3; margin-bottom: 1; }
    SenderCompareModal Input { width: 1fr; }
    SenderCompareModal Button { width: auto; min-width: 10; margin-left: 1; }
    SenderCompareModal TextArea { height: 1fr; border: none; }
    """

    def __init__(self, service, left_id):
        super().__init__()
        self.service, self.left_id = service, left_id

    def compose(self):
        with Vertical():
            yield Label("Compare Sender runs")
            with Horizontal():
                yield Input(str(self.left_id), placeholder="First run ID", type="integer", id="sender_compare_left", select_on_focus=False)
                yield Input(placeholder="Second run ID", type="integer", id="sender_compare_right", select_on_focus=False)
                yield ModalButton("Compare", id="sender_compare_go")
                yield ModalButton("Close", id="sender_compare_close")
            yield TextArea("", id="sender_compare_text", read_only=True, soft_wrap=False)

    def on_button_pressed(self, event):
        event.stop()
        if event.button.id == "sender_compare_close":
            self.dismiss()
        else:
            try:
                left = int(self.query_one("#sender_compare_left", Input).value)
                right = int(self.query_one("#sender_compare_right", Input).value)
            except ValueError:
                self.notify("Enter two run IDs", severity="error")
                return
            self.compare(left, right)

    @work(exclusive=True)
    async def compare(self, left, right):
        try:
            result = await sender_io(lambda: compare_sender_runs(self.service.get_run(left), self.service.get_run(right)))
            self.query_one("#sender_compare_text", TextArea).load_text(
                (result["diff"] or "No differences in request, sender identity or result.") +
                ("\n\nDiff truncated. Export both runs for the complete data." if result["truncated"] else ""))
        except Exception as error:
            self.notify(str(error), severity="error")


class SenderCaptureModal(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Cancel")]
    DEFAULT_CSS = """
    SenderCaptureModal { align: center middle; }
    SenderCaptureModal > Vertical { width: 85%; max-width: 90; height: auto; padding: 1 2; border: solid $foreground-muted; background: $surface; }
    SenderCaptureModal Label { margin-bottom: 1; }
    SenderCaptureModal Select { margin-bottom: 1; }
    SenderCaptureModal Horizontal { height: 3; align: right middle; }
    SenderCaptureModal Button { width: auto; min-width: 10; margin-left: 1; }
    """

    def __init__(self, entries):
        super().__init__()
        self.entries = entries

    def compose(self):
        with Vertical():
            yield Label("Prepare from captured Intent")
            yield Select([(label, index) for index, (label, _) in enumerate(self.entries)], value=0, allow_blank=False, id="sender_capture_source")
            yield Label("Sending operation")
            yield Select([(operation, operation) for operation in INTENT_OPERATIONS], prompt="Choose operation", id="sender_capture_operation")
            with Horizontal():
                yield ModalButton("Cancel", id="sender_capture_cancel")
                yield ModalButton("Prepare", id="sender_capture_prepare")

    def on_button_pressed(self, event):
        event.stop()
        if event.button.id == "sender_capture_cancel":
            self.dismiss(None)
            return
        try:
            operation = self.query_one("#sender_capture_operation", Select).value
            label, entry = self.entries[self.query_one("#sender_capture_source", Select).value]
            request = prepare_intent_request(entry, operation)
            self.dismiss({"id": None, "revision": 0, "name": label, "request": request})
        except (ValueError, TypeError) as error:
            self.notify(str(error), severity="error")


class SenderRequestModal(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Cancel")]
    DEFAULT_CSS = """
    SenderRequestModal { align: center middle; }
    SenderRequestModal > Vertical { width: 90%; max-width: 120; height: 90%; padding: 1 2; background: $surface; border: solid $foreground-muted; }
    SenderRequestModal .title { text-style: bold; margin-bottom: 1; }
    SenderRequestModal #sender_request_name { height: 3; margin-bottom: 1; }
    SenderRequestModal #sender_operation { height: 3; margin-bottom: 1; }
    SenderRequestModal #sender_request_body { height: 1fr; }
    SenderRequestModal #sender_fields { height: auto; }
    SenderRequestModal .buttons { height: 3; align: right middle; margin-top: 1; }
    SenderRequestModal Button { width: auto; min-width: 8; border: round $foreground-muted; background: transparent; }
    SenderRequestModal .buttons Button { min-width: 10; margin-left: 1; }
    SenderRequestModal Collapsible { background: transparent; }
    SenderRequestModal .editor_heading { text-style: bold; margin-top: 1; }
    """

    def __init__(self, service, saved=None):
        super().__init__()
        self.service, self.saved = service, saved
        request = saved["request"] if saved else empty_request()
        self.operation = request["operation"]
        self.drafts = {self.operation: copy.deepcopy(request)}
        self.fields = []

    def build_fields(self):
        request = self.drafts.setdefault(self.operation, empty_request(self.operation))
        intent = self.operation in INTENT_OPERATIONS
        body = request["intent"] if intent else request
        specs = object_fields("Intent") if intent else [("uri", "String", False, False)]
        if intent and self.operation in ("sendBroadcast", "sendOrderedBroadcast"):
            specs = [*specs, ("receiverPermission", "String", True, True)]
        if not intent:
            text_keys = {"query": ["selection", "sortOrder"], "update": ["selection"],
                         "delete": ["selection"], "call": ["method", "arg"]}.get(self.operation, [])
            specs += [(key, "String", key != "method", key != "method") for key in text_keys]
            if self.operation == "query":
                specs += [("maxRows", "int", True, False)]
            if self.operation in ("query", "openFileDescriptor"):
                specs += [("maxBytes", "int", True, False)]
        self.fields = []
        for key, kind, optional, nullable in specs:
            source = request if key == "receiverPermission" else body
            field = ScalarField(key, kind, source.get(key, MISSING), optional=optional, nullable=nullable,
                                input_id=f"sender_value_{key}")
            field.id = f"sender_field_{key}"
            self.fields.append(field)
        sections = object_sections("Intent") if intent else {
            "query": [("projection", "String[]"), ("selectionArgs", "String[]")],
            "insert": [("values", "ContentValues")],
            "update": [("values", "ContentValues"), ("selectionArgs", "String[]")],
            "delete": [("selectionArgs", "String[]")], "call": [("extras", "Bundle")],
        }.get(self.operation, [])
        for key, kind in sections:
            field = OptionalSection(key, kind, body.get(key, {} if key == "values" else MISSING),
                                    depth=1 if key == "selector" else 0, required=key == "values")
            self.fields.append(field)
        return self.fields

    def compose(self):
        with Vertical():
            with VerticalScroll(id="sender_request_body"):
                yield Label("Edit request" if self.saved else "New request", classes="title")
                yield Label("Name")
                yield Input(self.saved["name"] if self.saved else "", id="sender_request_name", select_on_focus=False)
                yield Label("Operation")
                yield Select([(op, op) for op in OPERATIONS], value=self.operation, allow_blank=False, id="sender_operation")
                with Vertical(id="sender_fields"):
                    yield from self.build_fields()
            with Horizontal(classes="buttons"):
                yield ModalButton("Cancel", id="sender_request_cancel")
                yield ModalButton("Save", id="sender_request_save")

    def collect_request(self):
        check_draft_ready(self)
        request = {"operation": self.operation}
        if self.operation in INTENT_OPERATIONS:
            request["intent"] = {}
        for field in self.fields:
            value = field.collect()
            if value is not MISSING:
                destination = request["intent"] if self.operation in INTENT_OPERATIONS and field.key != "receiverPermission" else request
                destination[field.key] = value
        return request

    async def on_select_changed(self, event):
        if event.select.id != "sender_operation":
            return
        event.stop()
        if is_select_empty(event.value) or self.operation == event.value:
            return
        try:
            self.drafts[self.operation] = self.collect_request()
        except ValueError as error:
            with event.select.prevent(Select.Changed):
                event.select.value = self.operation
            self.notify(str(error), severity="error")
            return
        with changing_draft(self):
            self.operation = event.value
            container = self.query_one("#sender_fields", Vertical)
            await container.remove_children()
            await container.mount(*self.build_fields())

    def on_button_pressed(self, event):
        event.stop()
        if event.button.id == "sender_request_cancel":
            self.dismiss(None)
        elif event.button.id == "sender_request_save":
            try:
                saved = self.service.save_request(
                    self.query_one("#sender_request_name", Input).value, self.collect_request(),
                    self.saved["id"] if self.saved else None, self.saved["revision"] if self.saved else 0)
            except (ValueError, OSError, sqlite3.Error) as error:
                self.notify(str(error), severity="error")
                return
            self.dismiss(saved)


class SenderPane(Vertical):
    DEFAULT_CSS = """
    SenderPane { height: 1fr; }
    SenderPane .sender_controls { height: 3; margin: 0 1; }
    SenderPane .sender_controls Button { width: auto; min-width: 9; margin-right: 1; border: round $foreground-muted; background: transparent; }
    SenderPane .sender_controls Input { width: 1fr; }
    SenderPane #sender_request_toolbar { layout: horizontal; }
    SenderPane #sender_request_actions { width: auto; height: 3; }
    SenderPane #sender_request_search_group { width: 1fr; height: 3; }
    SenderPane.compact-toolbar #sender_request_toolbar { layout: vertical; height: 6; }
    SenderPane.compact-toolbar #sender_request_search_group { width: 100%; }
    SenderPane #sender_device { width: 1fr; }
    SenderPane #sender_package { width: 2fr; }
    SenderPane #sender_pid { width: 12; }
    SenderPane #sender_app { width: 2fr; }
    SenderPane #sender_state { height: auto; margin: 0 1 1 1; }
    SenderPane DataTable { height: 1fr; border: none; background: $background; }
    SenderPane RichLog { height: 1fr; border: none; background: $background; }
    SenderPane .section_separator { height: 1; margin: 0; }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._requests = []
        self._runs = []
        self._signature = None
        self._devices = None
        self.applications = {}
        self._application_generation = 0
        self.run_depth = 200
        self.visible_columns = {table: {key for key, _ in columns} for table, columns in SENDER_COLUMNS.items()}
        self.widths = {table: {} for table in SENDER_COLUMNS}
        self.column_revision = 0
        self.sorts = {"sender_requests": ("name", False), "sender_runs": ("id", True)}
        self._checking_activity_send = False

    @property
    def service(self):
        return self.app.sender_service

    def compose(self):
        with Horizontal(classes="sender_controls"):
            yield Select([], id="sender_device", prompt="Device")
            yield Select([], id="sender_app", prompt="Running sender application")
            yield ModalButton("Refresh", id="sender_refresh")
            yield ModalButton("Connect", id="sender_connect")
            yield ModalButton("Disconnect", id="sender_disconnect")
        yield Label("Disconnected", id="sender_state", markup=False)
        with TabbedContent(initial="sender_requests_view", classes="subtabs", id="sender_views"):
            with TabPane("Requests", id="sender_requests_view"):
                with Vertical(id="sender_request_toolbar", classes="sender_controls"):
                    with Horizontal(id="sender_request_actions"):
                        yield ModalButton("+ New", id="sender_new")
                        yield ModalButton("From capture", id="sender_from_capture")
                        yield ModalButton("Edit", id="sender_edit")
                        yield ModalButton("Duplicate", id="sender_duplicate")
                        yield ModalButton("Remove", id="sender_remove")
                        yield ModalButton("Send", id="sender_send")
                    with Horizontal(id="sender_request_search_group"):
                        yield Input(placeholder="Search requests", id="sender_search", select_on_focus=False)
                        yield ModalButton("⊟", id="sender_request_columns", classes="sender_columns_button")
                yield Rule(classes="section_separator")
                yield DataTable(id="sender_requests", cursor_type="row")
                yield Rule(classes="section_separator")
                yield RichLog(id="sender_request_detail", markup=False, highlight=False, auto_scroll=False)
                yield Rule(classes="section_separator")
            with TabPane("Runs", id="sender_runs_view"):
                with Horizontal(classes="sender_controls"):
                    yield Input(placeholder="Search runs", id="sender_run_search", select_on_focus=False)
                    yield ModalButton("Compare", id="sender_compare")
                    yield ModalButton("Export", id="sender_export")
                    yield ModalButton("Cancel", id="sender_cancel_run")
                    yield ModalButton("Retry save", id="sender_retry_save")
                    yield ModalButton("⊟", id="sender_run_columns", classes="sender_columns_button")
                yield Rule(classes="section_separator")
                yield DataTable(id="sender_runs", cursor_type="row")
                yield Rule(classes="section_separator")
                yield RichLog(id="sender_run_detail", markup=False, highlight=False, auto_scroll=False)
                yield Rule(classes="section_separator")

    def on_resize(self):
        self.set_class(self.size.width < 90, "compact-toolbar")

    def on_mount(self):
        try:
            saved = json.loads(self.service.db.get_info("sender_columns", "{}"))
        except (ValueError, TypeError):
            saved = {}
        if isinstance(saved, dict):
            for table, columns in SENDER_COLUMNS.items():
                prefs = saved.get(table, {})
                if not isinstance(prefs, dict):
                    continue
                known = {key for key, _ in columns}
                if isinstance(prefs.get("visible"), list):
                    self.visible_columns[table] = {k for k in prefs["visible"] if isinstance(k, str) and k in known} or known
                self.widths[table] = normalize_column_widths(prefs.get("widths"), known)
        for table_id in SENDER_COLUMNS:
            self.set_table_columns(table_id)
        self.set_interval(0.3, self.refresh_sender)
        self.refresh_sender()

    def selected(self, table_id):
        table = self.query_one(f"#{table_id}", DataTable)
        if not table.row_count:
            return None
        key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        items = self._requests if table_id == "sender_requests" else self._runs
        return next((row for row in items if str(row["id"]) == key), None)

    def refresh_sender(self):
        devices = [(d.name, d.id) for d in self.app._home_devices]
        if devices != self._devices:
            self.query_one("#sender_device", Select).set_options(devices)
            self._devices = devices
        status = self.service.status()
        who = status["identity"]
        label = status["state"].capitalize()
        if who:
            label += f" · {who['package']} · UID {who['uid']} · PID {who['pid']}"
        if status["active_run"]:
            label += f" · Run #{status['active_run']} pending"
        if status["error"]:
            label += f" · {status['error']}"
        self.query_one("#sender_state", Label).update(Text(label))
        self.query_one("#sender_send", Button).disabled = (
            self._checking_activity_send or status["state"] != "ready" or status["active_run"] is not None
        )
        run_table = self.query_one("#sender_runs", DataTable)
        if run_table.row_count >= self.run_depth and run_table.scroll_y > 0 and run_table.scroll_y >= run_table.max_scroll_y - 3:
            self.run_depth += 200
        signature = (self.service.version, self.query_one("#sender_search", Input).value,
                     self.query_one("#sender_run_search", Input).value, dict(self.sorts), self.run_depth, self.column_revision)
        if signature == self._signature:
            return
        self._signature = signature
        self.load_rows(signature)

    @work(exclusive=True, group="sender_rows")
    async def load_rows(self, signature):
        try:
            requests = await sender_io(self.service.db.sender_requests)
            runs = await sender_io(self.service.db.sender_run_summaries, signature[2], signature[4], signature[3]["sender_runs"])
        except Exception as error:
            if self.is_mounted:
                self.notify(f"Could not read Sender records: {error}", severity="error")
            return
        if self._signature != signature:
            return
        for row in runs:
            if row["id"] in self.service.unsaved:
                row["state"] = self.service.unsaved[row["id"]]["state"]
        for table_id, rows, search in (("sender_requests", requests, signature[1]), ("sender_runs", runs, signature[2])):
            selected = self.selected(table_id)
            table = self.query_one(f"#{table_id}", DataTable)
            scroll = table.scroll_offset
            if table_id == "sender_requests":
                rows = [r for r in rows if search.casefold() in json.dumps(r, ensure_ascii=False).casefold()]
            key, reverse = self.sorts[table_id]
            rows.sort(key=lambda r: (r.get("request", {}).get(key, "") if key == "operation" else
                                    r.get("sender", {}).get("package", "") if key == "sender" else r.get(key, "")), reverse=reverse)
            table.clear(columns=True)
            self.set_table_columns(table_id)
            if table_id == "sender_requests":
                self._requests = rows
                for row in rows:
                    cells = {"name": Text(row["name"]), "operation": row["request"]["operation"], "revision": str(row["revision"])}
                    table.add_row(*(cells[k] for k, _ in SENDER_COLUMNS[table_id] if k in self.visible_columns[table_id]), key=row["id"])
            else:
                self._runs = rows
                for row in rows:
                    cells = {"id": str(row["id"]), "name": Text(row["name"]), "state": row["state"],
                             "sender": Text(row["sender"]["package"]), "createdAt": row["createdAt"]}
                    table.add_row(*(cells[k] for k, _ in SENDER_COLUMNS[table_id] if k in self.visible_columns[table_id]), key=str(row["id"]))
            if selected:
                index = next((i for i, row in enumerate(rows) if row["id"] == selected["id"]), 0)
                table.move_cursor(row=index)
            table.scroll_to(x=scroll.x, y=scroll.y, animate=False, force=True)
            self.show_detail(table_id)

    def set_table_columns(self, table_id):
        table = self.query_one(f"#{table_id}", DataTable)
        sort, reverse = self.sorts[table_id]
        for key, title in SENDER_COLUMNS[table_id]:
            if key in self.visible_columns[table_id]:
                label = title + (" ↓" if reverse else " ↑") if key == sort else title
                table.add_column(label, key=key, width=self.widths[table_id].get(key))

    def change_columns(self, table_id, visible=None, widths=None):
        preferences = {table: {"visible": sorted(self.visible_columns[table]), "widths": dict(self.widths[table])} for table in SENDER_COLUMNS}
        if visible is not None:
            preferences[table_id]["visible"] = sorted(visible)
        if widths is not None:
            preferences[table_id]["widths"] = widths
        try:
            self.service.db.set_info("sender_columns", json.dumps(preferences))
        except (OSError, sqlite3.Error) as error:
            self.notify(f"Could not save column preferences: {error}", severity="error")
            return
        self.visible_columns[table_id] = set(preferences[table_id]["visible"])
        self.widths[table_id] = preferences[table_id]["widths"]
        self.column_revision += 1
        self.refresh_sender()

    def show_detail(self, table_id):
        row = self.selected(table_id)
        detail = self.query_one("#sender_request_detail" if table_id == "sender_requests" else "#sender_run_detail", RichLog)
        detail.clear()
        if row:
            if table_id == "sender_requests":
                detail.write(render_sender_detail(row))
            else:
                self.show_run_detail(row["id"])

    @work(exclusive=True, group="sender_detail")
    async def show_run_detail(self, run_id):
        try:
            row = await sender_io(self.service.get_run, run_id)
        except Exception as error:
            self.notify(str(error), severity="error")
            return
        selected = self.selected("sender_runs")
        if selected is not None and selected["id"] == run_id:
            self.query_one("#sender_run_detail", RichLog).write(render_sender_detail(row))

    def on_data_table_row_highlighted(self, event):
        event.stop()
        self.show_detail(event.data_table.id)

    def on_data_table_header_selected(self, event):
        event.stop()
        table_id, key = event.data_table.id, event.column_key.value
        previous, reverse = self.sorts[table_id]
        self.sorts[table_id] = (key, not reverse if previous == key else False)
        self.refresh_sender()

    def on_select_changed(self, event):
        event.stop()
        if event.select.id == "sender_device":
            self._application_generation += 1
            self.applications = {}
            self.query_one("#sender_app", Select).set_options([])
            if not is_select_empty(event.value):
                self.load_applications(event.value, self._application_generation)

    def active_table(self):
        return "sender_runs" if self.query_one("#sender_views", TabbedContent).active == "sender_runs_view" else "sender_requests"

    def on_tabbed_content_tab_activated(self, event):
        if event.tabbed_content.id == "sender_views":
            event.stop()
            self.app.refresh_bindings()
            if self.app._active_tab == "tab_sender":
                self.query_one(f"#{self.active_table()}", DataTable).focus()

    def adjust_detail(self, delta):
        table = self.query_one(f"#{self.active_table()}", DataTable)
        detail = self.query_one("#sender_run_detail" if table.id == "sender_runs" else "#sender_request_detail", RichLog)
        available = table.size.height + detail.size.height
        table.styles.height = max(3, min(available - 3, table.size.height - delta))

    @work(group="sender_apps")
    async def load_applications(self, device_id, generation):
        devices = self.app._home_devices
        resolver = getattr(devices, "get_device", None)
        if resolver is None:
            return
        try:
            def scan():
                return resolver(device_id, timeout=5).enumerate_applications()
            applications = await sender_io(scan)
            if generation != self._application_generation:
                return
            self.applications = {f"{a.identifier}:{a.pid}": a for a in applications if a.pid}
            self.query_one("#sender_app", Select).set_options([
                (f"{a.name} · {a.identifier} · {a.pid}", key)
                for key, a in sorted(self.applications.items(), key=lambda item: item[1].name.casefold())])
        except Exception as error:
            if generation == self._application_generation:
                self.notify(str(error), severity="error")

    @work(group="sender_controls")
    async def connect_sender(self, device, package, pid, token):
        try:
            endpoint = endpoint_for_app(self.app, device, pid)
            await self.service.connect(endpoint, package, token)
        except Exception as error:
            self.notify(str(error), severity="error")
        self.refresh_sender()

    def dispatch_request(self, row, token):
        run = self.service.execute(row["id"], row["revision"], token, uuid4().hex)
        self.notify(f"Sender run #{run['id']} started")

    @work(group="sender_controls")
    async def send_activity(self, row, token):
        try:
            context = await self.service.activity_context(token)
            if context["state"] == "background":
                confirmed = await self.app.push_screen_wait(RecordingDialog(
                    f"{context['package']} is running in the background. "
                    "Android may block the Activity launch.\n\n"
                    "To retry from the foreground, cancel and open the sender app on Android.",
                    "Send anyway",
                ))
                if not confirmed:
                    return
            self.dispatch_request(row, token)
        except Exception as error:
            self.notify(str(error), severity="error")
        finally:
            self._checking_activity_send = False
            if self.is_mounted:
                self.refresh_sender()

    async def on_button_pressed(self, event):
        event.stop()
        button = event.button.id
        try:
            if button == "sender_connect":
                device = self.query_one("#sender_device", Select).value
                if is_select_empty(device):
                    raise ValueError("Select a device")
                application = self.applications.get(self.query_one("#sender_app", Select).value)
                if application is None:
                    raise ValueError("Choose a running app; open it on the device and Refresh if needed")
                self.connect_sender(device, application.identifier, application.pid, self.service.token)
            elif button == "sender_refresh":
                device = self.query_one("#sender_device", Select).value
                if not is_select_empty(device):
                    self._application_generation += 1
                    self.load_applications(device, self._application_generation)
            elif button == "sender_disconnect":
                await self.service.disconnect(self.service.token)
            elif button == "sender_cancel_run":
                run = self.selected("sender_runs")
                if run:
                    await self.service.cancel(run["id"], self.service.token)
            elif button in ("sender_export", "sender_compare"):
                run = self.selected("sender_runs")
                if run:
                    if button == "sender_compare":
                        self.app.push_screen(SenderCompareModal(self.service, run["id"]))
                    else:
                        result = await sender_io(lambda: write_sender_export(self.service.get_run(run["id"])))
                        self.notify(f"Exported {result.filename}")
            elif button == "sender_retry_save":
                self.service.retry_save()
            elif button in ("sender_request_columns", "sender_run_columns"):
                table = "sender_requests" if button == "sender_request_columns" else "sender_runs"
                self.app.push_screen(ColumnSelectModal(self.visible_columns[table],
                    lambda visible: self.change_columns(table, visible=visible), SENDER_COLUMNS[table], self.widths[table],
                    lambda widths: self.change_columns(table, widths=widths),
                    resizable_keys={key for key, _ in SENDER_COLUMNS[table]}, select_width_on_focus=False))
            elif button == "sender_new":
                self.app.push_screen(SenderRequestModal(self.service), lambda _: self.refresh_sender())
            elif button == "sender_from_capture":
                import copy
                entries = []
                for label, entry in (("History", self.app._history_selected_entry),
                                     ("Intercept", self.app._current_intercepted_entry)):
                    if entry:
                        entries.append((f"{label} #{entry.get('id', '')}", copy.deepcopy(entry)))
                if not entries:
                    raise ValueError("Select an Intent in History or hold one in Intercept first")
                def prepared(draft):
                    if draft:
                        self.app.push_screen(SenderRequestModal(self.service, draft), lambda _: self.refresh_sender())
                self.app.push_screen(SenderCaptureModal(entries), prepared)
            else:
                row = self.selected("sender_requests")
                if row is None:
                    return
                if button == "sender_edit":
                    self.app.push_screen(SenderRequestModal(self.service, row), lambda _: self.refresh_sender())
                elif button == "sender_duplicate":
                    self.service.save_request(row["name"] + " copy", row["request"])
                elif button == "sender_remove":
                    self.service.remove_request(row["id"], row["revision"])
                elif button == "sender_send":
                    if self._checking_activity_send:
                        return
                    if row["request"]["operation"] == "startActivity":
                        self._checking_activity_send = True
                        self.send_activity(row, self.service.token)
                    else:
                        self.dispatch_request(row, self.service.token)
            self.refresh_sender()
        except Exception as error:
            self.notify(str(error), severity="error")
