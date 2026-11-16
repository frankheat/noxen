"""Sender requests and execution records. UI and MCP share SenderService."""

import copy
import json
import re
import sqlite3
from uuid import uuid4

from rich.text import Text
from textual import work
from textual.containers import Horizontal, HorizontalScroll, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, OptionList, RichLog, Rule, Select, Tree, Collapsible
from textual.widgets.option_list import Option

from noxen.modals import ModalButton
from noxen.monitor_ui import RecordingDialog
from noxen.sender import OPERATIONS, INTENT_OPERATIONS, SenderError, empty_request, render_sender_detail
from noxen.sender_service import endpoint_for_app, sender_io
from noxen.textual_compat import is_select_empty
from noxen import sender_json
from noxen.sender_json_editor import JsonRequestEditor
from noxen.sender_editor import MISSING, ScalarField, OptionalSection, object_fields, object_sections, ValueEditor, EntryRow, SCALARS, LABELS, changing_draft, check_draft_ready


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
    /* Sections and nested objects are hidden until navigation opens them, so
       a newly mounted one never shows before it has been placed. */
    SenderRequestModal OptionalSection { display: none; }
    SenderRequestModal OptionalSection.navigation_target,
    SenderRequestModal OptionalSection.navigation_path { display: block; }
    SenderRequestModal EntryRow > .entry_body { display: none; }
    SenderRequestModal EntryRow > .entry_body.navigation_path { display: block; }
    SenderRequestModal .off_path { display: none; }
    """

    def __init__(self, service, saved=None):
        super().__init__()
        self.service, self.saved = service, saved
        request = saved["request"] if saved else empty_request()
        self.operation = request["operation"]
        self.drafts = {self.operation: copy.deepcopy(request)}
        self.fields = []
        self._object_target = None
        self._navigation_signature = None

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
            yield Label("Edit request" if self.saved and self.saved["id"] else "New request", classes="title")
            with Horizontal(id="sender_workspace"):
                tree = Tree("Request", id="sender_request_tree")
                tree.auto_expand = False  # A click opens the object; it must not fold the explorer.
                tree.guide_depth = 3
                yield tree
                with VerticalScroll(id="sender_request_body"):
                    yield Label("Request", id="sender_object_title", classes="title")
                    with Vertical(id="sender_request_identity"):
                        yield Label("Name")
                        yield Input(self.saved["name"] if self.saved else "", id="sender_request_name", select_on_focus=False)
                        yield Label("Operation")
                        yield Select([(op, op) for op in OPERATIONS], value=self.operation, allow_blank=False, id="sender_operation")
                    with Vertical(id="sender_fields"):
                        yield from self.build_fields()
            with Horizontal(classes="buttons"):
                yield ModalButton("Browse", id="sender_request_browse")
                yield ModalButton("Cancel", id="sender_request_cancel")
                yield ModalButton("Save", id="sender_request_save")

    def on_mount(self):
        self.refresh_navigation()
        self.set_interval(0.2, self.refresh_navigation)

    def on_resize(self, event):
        self.set_class(event.size.width < 90, "narrow_request")

    def navigation_items(self):
        items = []
        def visit(widget, parent, label):
            items.append((widget, parent, label))
            editor = widget.editor if isinstance(widget, OptionalSection) else widget
            if editor is None:
                return
            for child in editor.members:
                if isinstance(child, OptionalSection):
                    visit(child, widget, LABELS.get(child.key, child.key.capitalize()))
                elif isinstance(child, EntryRow) and child.editor is not None and child.kind not in SCALARS:
                    key = child.key_field.query_one(Input).value if child.is_map else f"Item {child.key}"
                    visit(child.editor, widget, f"{key or '(empty key)'} · {child.kind}")
        for field in self.fields:
            if isinstance(field, OptionalSection):
                visit(field, None, LABELS.get(field.key, field.key.capitalize()))
        return items

    def refresh_navigation(self):
        if not self.query("#sender_request_tree"):
            return  # The timer can fire once more while the editor is closing.
        if getattr(self, "_changing_draft", False) or any(getattr(w, "_changing_draft", False) for w in self.query()):
            return
        items = self.navigation_items()
        signature = tuple((id(w), id(p), label, getattr(w, "editor", w) is None) for w, p, label in items)
        if signature == self._navigation_signature:
            return
        self._navigation_signature = signature
        tree = self.query_one("#sender_request_tree", Tree)
        tree.clear()
        nodes = {None: tree.root}
        for widget, parent, label in items:
            has_children = any(p is widget for _, p, _ in items)
            unset = isinstance(widget, OptionalSection) and widget.editor is None
            caption = Text("+ " + label, style="dim") if unset else Text(label)
            nodes[widget] = nodes[parent].add(caption, data=widget, expand=True, allow_expand=has_children)
        tree.root.expand()
        self._navigation_nodes = nodes
        if self._object_target not in nodes:
            self._object_target = None
        tree.move_cursor(nodes[self._object_target])
        self.focus_request_object(self._object_target, scroll=False)

    def on_tree_node_selected(self, event):
        if event.control.id == "sender_request_tree":
            event.stop()
            self.focus_request_object(event.node.data)
            self.remove_class("browse_request")

    def focus_request_object(self, target, *, scroll=True):
        with self.app.batch_update():  # One repaint: no half-updated form in between.
            self._show_request_object(target, scroll)

    def _show_request_object(self, target, scroll):
        self._object_target = target
        node = getattr(self, "_navigation_nodes", {}).get(target)
        if node is not None:
            self.query_one("#sender_request_tree", Tree).move_cursor(node)
        # Everything stays mounted so the draft survives navigation. Only the
        # chain from the fields down to the target is shown, without the
        # headings and buttons that belong to the levels above it.
        # Classes change without a per-widget restyle; one pass follows.
        fields = self.query_one("#sender_fields")
        for name in ("off_path", "navigation_path", "navigation_target"):
            for widget in fields.query("." + name):
                widget.remove_class(name, update=False)
        if target is not None:
            target.add_class("navigation_target", update=False)
            current = target
            while current is not fields:
                parent = current.parent
                for sibling in parent.children:
                    own_null = sibling.has_class("set_null") and getattr(parent.parent, "editor", None) is target
                    if sibling is not current and not own_null:
                        sibling.add_class("off_path", update=False)
                if parent is not fields:
                    parent.add_class("navigation_path", update=False)
                if isinstance(parent, Collapsible):
                    parent.collapsed = False
                current = parent
        self.app.update_styles(fields)
        self.query_one("#sender_request_identity").display = target is None
        labels = {w: (p, label) for w, p, label in self.navigation_items()}
        path = []
        current = target
        while current in labels:
            current, label = labels[current]
            path.append(label)
        title = "Request" if not path else " / ".join(reversed(path))
        # The title shares a row with the object's own Add / Remove buttons when it has them.
        previous = getattr(self, "_title_slot", None)
        if previous is not None and previous[0].is_attached:
            previous[0].update(previous[1])
        slot = None
        if isinstance(target, OptionalSection):
            slot = target.query_one(".section_header > Label", Label)
            self._title_slot = (slot, LABELS.get(target.key, target.key.capitalize()))
        elif isinstance(target, ValueEditor) and target.query(".add_row > .add_title"):
            slot = target.query_one(".add_row > .add_title", Label)
            self._title_slot = (slot, "")
        else:
            self._title_slot = None
        heading = self.query_one("#sender_object_title", Label)
        heading.display = slot is None
        (slot or heading).update(Text(title))
        if scroll:
            self.query_one("#sender_request_body", VerticalScroll).scroll_home(animate=False)

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
        # One repaint for the whole swap: no empty form, no unplaced sections.
        with self.app.batch_update():
            with changing_draft(self):
                self.operation = event.value
                container = self.query_one("#sender_fields", Vertical)
                await container.remove_children()
                await container.mount(*self.build_fields())
            self.refresh_navigation()

    def on_button_pressed(self, event):
        event.stop()
        if event.button.id == "sender_request_browse":
            self.toggle_class("browse_request")
        elif event.button.id == "sender_request_cancel":
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


class SenderTabMenu(ModalScreen):
    """A short menu opened at a screen position: the request tab actions by default."""

    BINDINGS = [("escape", "dismiss", "Close")]
    DEFAULT_CSS = """
    SenderTabMenu { align: left top; background: transparent; }
    SenderTabMenu OptionList { width: auto; height: auto; border: round $foreground-muted; background: $surface; }
    """

    def __init__(self, x, y, options=(("Edit", "edit"), ("Duplicate", "duplicate"), ("Remove", "remove"))):
        super().__init__()
        self.position, self.options = (x, y), options

    def compose(self):
        yield OptionList(*(Option(label, id=key) for label, key in self.options))

    def on_mount(self):
        menu = self.query_one(OptionList)
        x, y = self.position
        width = max(len(label) for label, _ in self.options) + 6
        menu.styles.width = width
        menu.styles.offset = (max(0, min(x, self.size.width - width)),
                              max(0, min(y, self.size.height - len(self.options) - 2)))
        menu.focus()

    def on_option_list_option_selected(self, event):
        event.stop()
        self.dismiss(event.option.id)

    def on_click(self, event):
        if event.widget is self:
            self.dismiss(None)


class RequestTab(ModalButton):
    """One saved request, labelled with its name."""

    def __init__(self, row):
        name = row["name"]
        super().__init__(Text(name if len(name) <= 24 else name[:23] + "…"), classes="request_tab",
                         tooltip=None if len(name) <= 24 else name)
        self.request_id = row["id"]

    def on_click(self, event):
        if event.button == 3:
            event.stop()
            self.screen.query_one(SenderPane).open_tab_menu(self.request_id, event.screen_x, event.screen_y)


class SenderPane(Vertical):
    DEFAULT_CSS = """
    SenderPane { height: 1fr; }
    SenderPane .sender_controls { height: 3; margin: 0 1; }
    SenderPane Button { width: auto; min-width: 0; margin-right: 1; border: round $foreground-muted; background: transparent; }
    SenderPane #sender_device { width: 1fr; margin-right: 1; }
    SenderPane #sender_app { width: 2fr; margin-right: 1; }
    SenderPane #sender_state { height: auto; margin: 0 1 1 1; }
    SenderPane #sender_tabs { height: auto; max-height: 4; margin: 0 1; scrollbar-size-horizontal: 1; }
    SenderPane #sender_new { height: 3; min-width: 5; border: none; }
    SenderPane #sender_tabs .request_tab.-selected { border: round $accent; color: $accent; }
    SenderPane #sender_split { height: 1fr; }
    SenderPane .sender_side { width: 1fr; height: 1fr; margin: 0 1; }
    SenderPane #sender_result_side { border-left: solid $foreground-muted; padding-left: 1; }
    SenderPane.stacked #sender_result_side { border-left: none; padding-left: 0; }
    SenderPane .side_header { height: 3; }
    SenderPane .side_header > Label { width: 1fr; height: 3; margin-left: 1; content-align: left middle; text-style: bold; }
    SenderPane RichLog { height: 1fr; border: none; background: $background; }
    SenderPane .section_separator { height: 1; margin: 0; }
    SenderPane.stacked #sender_split { layout: vertical; }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._requests = []
        self._selected_id = None
        self._signature = None
        self._tab_signature = None
        self._devices = None
        self.applications = {}
        self._application_generation = 0
        self._checking_activity_send = False
        self._run_ids = []      # Runs of the selected request, newest first.
        self._run_id = None     # None follows the latest run.
        self._editor_key = None       # What the JSON editor shows: (request id, revision) or ("run", id).
        self._editor_baseline = ""    # Its text as saved, to tell edits apart.
        self._drafts = {}             # Unsaved text of requests that are not on screen.

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
        with HorizontalScroll(id="sender_tabs"):
            yield ModalButton("+", id="sender_new")
        yield Rule(classes="section_separator")
        with Horizontal(id="sender_split"):
            with Vertical(classes="sender_side", id="sender_request_side"):
                with Horizontal(classes="side_header"):
                    yield ModalButton("Send", id="sender_send")
                    yield ModalButton("Cancel", id="sender_cancel_run", tooltip="Ask a running query or file read to stop")
                    yield ModalButton("Edit", id="sender_edit")
                    yield ModalButton("Save", id="sender_save")
                yield JsonRequestEditor(id="sender_request_detail")
            with Vertical(classes="sender_side", id="sender_result_side"):
                with Horizontal(classes="side_header"):
                    yield ModalButton("‹", id="sender_run_older")
                    yield ModalButton("›", id="sender_run_newer")
                    yield Label("Result", id="sender_result_title", markup=False)
                yield RichLog(id="sender_run_detail", markup=False, highlight=False, auto_scroll=False, wrap=True)
        yield Rule(classes="section_separator")

    def on_resize(self):
        self.set_class(self.size.width < 100, "stacked")

    def on_mount(self):
        self.set_interval(0.3, self.refresh_sender)
        self.refresh_sender()

    def selected(self):
        return next((row for row in self._requests if row["id"] == self._selected_id), None)

    @property
    def editor(self):
        return self.query_one(JsonRequestEditor)

    def editor_dirty(self):
        area = self.editor.area
        return not area.read_only and area.full_text() != self._editor_baseline

    def show_editor_state(self):
        row, area = self.selected(), self.editor.area
        self.query_one("#sender_save", Button).disabled = not self.editor_dirty()
        if row is None or area.read_only:
            return
        self.editor.say("Modified · Ctrl+S save" if self.editor_dirty() else
                        f"Revision {row['revision']} · Ctrl+Space suggest · F2 fold")

    def on_text_area_changed(self, event):
        event.stop()
        self.show_editor_state()

    def on_json_area_save(self, event):
        event.stop()
        self.save_editor()

    def save_editor(self):
        """Save the JSON on screen as a new revision. Returns the saved request, or None if it is not valid."""
        row, area = self.selected(), self.editor.area
        if row is None or area.read_only:
            return row
        if not self.editor_dirty():
            return row
        try:
            saved = self.service.save_request(row["name"], sender_json.parse(area.text, area.folds),
                                              row["id"], row["revision"])
        except (ValueError, OSError, sqlite3.Error) as error:
            self.editor.say(str(error), error=True)
            if (line := re.match(r"Line (\d+), column (\d+)", str(error))) and not area.folds:
                area.move_cursor((int(line.group(1)) - 1, int(line.group(2)) - 1))
            area.focus()
            return None
        self._editor_baseline = area.full_text()
        self._editor_key = (saved["id"], saved["revision"])
        self._requests = [dict(r, revision=saved["revision"], request=saved["request"]) if r["id"] == saved["id"] else r
                          for r in self._requests]
        self.editor.say(f"Saved · revision {saved['revision']}")
        self.query_one("#sender_save", Button).disabled = True
        return self.selected()

    def show_request_json(self, row, run):
        """Put the right text in the editor without discarding what the user is typing."""
        area = self.editor.area
        if row is None:
            self._editor_key, self._editor_baseline = None, ""
            area.read_only = True
            area.load("")
            self.editor.say("No requests yet. Press + to create one.")
        elif run is not None and self._run_id is not None:
            key = ("run", run["id"])
            if key != self._editor_key:
                self.stash_draft()
                self._editor_key, self._editor_baseline = key, ""
                area.read_only = True
                area.load(sender_json.format_request(run["request"]))
            note = f"As sent in run #{run['id']} · read only"
            if run["revision"] != row["revision"]:
                note += f" · the request is now at revision {row['revision']}"
            self.editor.say(note)
        else:
            key = (row["id"], row["revision"])
            same_request = self._editor_key is not None and self._editor_key[0] == row["id"]
            if key != self._editor_key and same_request and self.editor_dirty():
                self.editor.say(f"Changed elsewhere (revision {row['revision']}); saving will report the conflict",
                                error=True)
                return
            if key != self._editor_key:
                self.stash_draft()
                saved_text = sender_json.format_request(row["request"])
                text, folds = self._drafts.pop(row["id"], (saved_text, {}))
                self._editor_key, self._editor_baseline = key, saved_text
                area.read_only = False
                area.load(text, folds)
            self.show_editor_state()
        self.query_one("#sender_save", Button).disabled = not self.editor_dirty()

    def stash_draft(self):
        """Keep unsaved text of the request leaving the editor, so switching tabs loses nothing."""
        key = self._editor_key
        if key is not None and key[0] != "run" and self.editor_dirty():
            area = self.editor.area
            self._drafts[key[0]] = (area.text, dict(area.folds))

    def select_request(self, request_id):
        if request_id != self._selected_id:
            self._run_id = None
        self._selected_id = request_id
        for tab in self.query(RequestTab):
            tab.set_class(tab.request_id == request_id, "-selected")
        self.refresh_sender()

    def focus_default(self):
        tab = next((t for t in self.query(RequestTab) if t.request_id == self._selected_id), None)
        (tab or self.query_one("#sender_new", Button)).focus()

    def refresh_sender(self):
        devices = [(d.name, d.id) for d in self.app._home_devices]
        if devices != self._devices:
            self.query_one("#sender_device", Select).set_options(devices)
            self._devices = devices
        status = self.service.status()
        label = status["state"].capitalize()
        if status["active_run"]:
            label += f" · Run #{status['active_run']} pending"
        if status["error"]:
            label += f" · {status['error']}"
        self.query_one("#sender_state", Label).update(Text(label))
        self.query_one("#sender_disconnect", Button).disabled = status["state"] == "disconnected"
        row = self.selected()
        self.query_one("#sender_send", Button).disabled = (
            self._checking_activity_send or status["state"] != "ready" or status["active_run"] is not None
            or row is None
        )
        self.query_one("#sender_edit", Button).disabled = row is None
        self.query_one("#sender_cancel_run", Button).disabled = not (
            row is not None and status["active_run"] is not None and status["active_run"] in self._run_ids[:1]
            and row["request"]["operation"] in ("query", "openFileDescriptor"))
        signature = (self.service.version, self._selected_id, self._run_id)
        if signature == self._signature:
            return
        self._signature = signature
        self.load_rows(signature)

    @work(exclusive=True, group="sender_rows")
    async def load_rows(self, signature):
        try:
            requests = sorted(await sender_io(self.service.db.sender_requests), key=lambda row: row["number"])
            if not any(row["id"] == self._selected_id for row in requests):
                self._selected_id = requests[0]["id"] if requests else None
            run_ids = [] if self._selected_id is None else await sender_io(
                self.service.db.sender_run_ids, self._selected_id)
            run_id = self._run_id if self._run_id in run_ids else run_ids[0] if run_ids else None
            run = None if run_id is None else await sender_io(self.service.get_run, run_id)
        except Exception as error:
            if self.is_mounted:
                self.notify(f"Could not read Sender records: {error}", severity="error")
            return
        if self._signature != signature:
            return
        self._requests, self._run_ids = requests, run_ids
        if self._run_id not in run_ids:
            self._run_id = None
        position = run_ids.index(run_id) if run_ids else 0
        self.query_one("#sender_run_older", Button).disabled = position >= len(run_ids) - 1
        self.query_one("#sender_run_newer", Button).disabled = position == 0
        self.query_one("#sender_result_title", Label).update(
            Text(f"Result · run {len(run_ids) - position} of {len(run_ids)}" if run_ids else "Result"))
        await self.show_tabs()
        row = self.selected()
        result_log = self.query_one("#sender_run_detail", RichLog)
        result_log.clear()
        # An earlier run is shown with the request exactly as it was sent.
        self.show_request_json(row, run)
        if row is not None:
            if run is None:
                result_log.write(Text("Not sent yet.", style="dim"))
            else:
                result_log.write(render_sender_detail(
                    run, current_revision=run["revision"] if self._run_id is not None else row["revision"]))
        # A stale signature means the selection moved while this ran; read again.
        if (self.service.version, self._selected_id, self._run_id) != signature:
            self.refresh_sender()

    async def show_tabs(self):
        tabs = self.query_one("#sender_tabs", HorizontalScroll)
        signature = tuple((row["id"], row["name"]) for row in self._requests)
        if signature != self._tab_signature:
            self._tab_signature = signature
            with self.app.batch_update():
                await tabs.remove_children(RequestTab)
                if self._requests:
                    await tabs.mount(*(RequestTab(row) for row in self._requests), before="#sender_new")
        for tab in tabs.query(RequestTab):
            tab.set_class(tab.request_id == self._selected_id, "-selected")
            if tab.request_id == self._selected_id:
                # After layout: a tab mounted in this pass has no position yet.
                self.call_after_refresh(tab.scroll_visible, animate=False)

    def on_select_changed(self, event):
        event.stop()
        if event.select.id == "sender_device":
            self._application_generation += 1
            self.applications = {}
            self.query_one("#sender_app", Select).set_options([])
            if not is_select_empty(event.value):
                self.load_applications(event.value, self._application_generation)

    def adjust_detail(self, delta):
        """Alt+Left / Alt+Right move the divider between request and result."""
        left = self.query_one("#sender_request_side")
        total = self.query_one("#sender_split").size.width
        if self.has_class("stacked") or total < 60:
            return
        left.styles.width = max(24, min(total - 28, left.size.width + delta * 4))

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

    def next_name(self):
        """New requests are named with the next free number; the name is the tab label."""
        names = [row["name"] for row in self.service.db.sender_requests()]  # Not the last refresh: it may be stale.
        return str(max([int(name) for name in names if name.isdecimal()], default=0) + 1)

    def receive_request(self, request):
        """Add a request prepared in another tab. One that fails validation opens in the editor instead."""
        name = self.next_name()
        try:
            saved = self.service.save_request(name, request)
        except SenderError as error:
            self.notify(f"{error}. Review the request before saving it.", severity="warning")
            self.edit_request({"id": None, "revision": 0, "name": name, "request": request})
            return
        self.select_request(saved["id"])
        self.notify(f"Sent to Sender as request {name}")

    def browse_runs(self, step):
        if self._run_ids:
            current = self._run_ids.index(self._run_id) if self._run_id in self._run_ids else 0
            target = max(0, min(len(self._run_ids) - 1, current + step))
            self._run_id = None if target == 0 else self._run_ids[target]

    def dispatch_request(self, row, token):
        self._run_id = None  # Show the run that is about to start.
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

    def edit_request(self, draft):
        def saved(result):
            if result:
                self.select_request(result["id"])
            self.refresh_sender()
        self.app.push_screen(SenderRequestModal(self.service, draft), saved)

    def open_tab_menu(self, request_id, x, y):
        self.select_request(request_id)
        def chosen(action):
            row = self.service.db.sender_request(request_id) if action else None
            if row is None:
                return
            try:
                if action == "edit":
                    self.edit_request(row)
                elif action == "duplicate":
                    name = self.next_name() if row["name"].isdecimal() else (row["name"] + " copy")[:200]
                    self.select_request(self.service.save_request(name, row["request"])["id"])
                elif action == "remove":
                    self.service.remove_request(row["id"], row["revision"])
                self.refresh_sender()
            except Exception as error:
                self.notify(str(error), severity="error")
        self.app.push_screen(SenderTabMenu(x, y), chosen)

    async def on_button_pressed(self, event):
        event.stop()
        button = event.button.id
        try:
            if isinstance(event.button, RequestTab):
                self.select_request(event.button.request_id)
            elif button == "sender_connect":
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
            elif button == "sender_new":
                self.edit_request({"id": None, "revision": 0, "name": self.next_name(), "request": empty_request()})
            elif button == "sender_save":
                self.save_editor()
            elif button == "sender_edit":
                # The form edits the saved request, so what is typed here is saved first.
                row = self.save_editor()
                if row is not None:
                    self.edit_request(row)
            elif button == "sender_cancel_run":
                status = self.service.status()
                if status["active_run"] is not None:
                    await self.service.cancel(status["active_run"], self.service.token)
            elif button in ("sender_run_older", "sender_run_newer"):
                self.browse_runs(1 if button == "sender_run_older" else -1)
            elif button == "sender_send":
                row = self.save_editor()  # Send what is on screen.
                if row is None or self._checking_activity_send:
                    return
                if row["request"]["operation"] == "startActivity":
                    self._checking_activity_send = True
                    self.send_activity(row, self.service.token)
                else:
                    self.dispatch_request(row, self.service.token)
            self.refresh_sender()
        except Exception as error:
            self.notify(str(error), severity="error")
