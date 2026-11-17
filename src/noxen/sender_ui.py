"""Sender requests and execution records. UI and MCP share SenderService."""

import re
import sqlite3
from uuid import uuid4

from rich.text import Text
from textual import work
from textual.containers import Horizontal, HorizontalScroll, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, OptionList, RichLog, Rule, Select
from textual.widgets.option_list import Option

from noxen.modals import ModalButton
from noxen.monitor_ui import RecordingDialog
from noxen.sender import SenderError, render_sender_detail
from noxen.sender_service import endpoint_for_app, sender_io
from noxen.textual_compat import is_select_empty
from noxen import sender_json
from noxen.sender_json_editor import JsonRequestEditor


AUTOSAVE_DELAY = 0.8
# A new request has no operation yet. The editor shows where to write one.
NEW_REQUEST_TEXT = '{\n    "operation": ""\n}'


def request_text(request):
    """The editor text of a saved request."""
    return NEW_REQUEST_TEXT if request == {} else sender_json.format_request(request)


class SenderRenameModal(ModalScreen):
    """Rename a request. The name is what its tab shows."""

    BINDINGS = [("escape", "dismiss", "Cancel")]
    DEFAULT_CSS = """
    SenderRenameModal { align: center middle; }
    SenderRenameModal > Vertical { width: 60; max-width: 90%; height: auto; padding: 1 2; background: $surface; border: solid $foreground-muted; }
    SenderRenameModal Label { margin-bottom: 1; text-style: bold; }
    SenderRenameModal Input { height: 3; padding: 0 1; border: round $foreground-muted; }
    SenderRenameModal Input:focus { border: round $accent; }
    """

    def __init__(self, name):
        super().__init__()
        self.current = name

    def compose(self):
        with Vertical():
            yield Label("Rename request")
            yield Input(self.current, id="sender_rename", select_on_focus=True)

    def on_mount(self):
        self.query_one(Input).focus()

    def on_input_submitted(self, event):
        event.stop()
        self.dismiss(event.value)


class SenderTabMenu(ModalScreen):
    """A short menu opened at a screen position: the request tab actions by default."""

    BINDINGS = [("escape", "dismiss", "Close")]
    DEFAULT_CSS = """
    SenderTabMenu { align: left top; background: transparent; }
    SenderTabMenu OptionList { width: auto; height: auto; border: round $foreground-muted; background: $surface; }
    """

    def __init__(self, x, y, options=(("Rename", "rename"), ("Duplicate", "duplicate"), ("Close", "close"))):
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
        self._autosave = None         # Pending timer of the automatic save.
        self._retry_save = False      # The last save failed for a reason other than the text.
        self._result_shown = None     # What the result panel currently describes.
        self._suggest_on_load = None  # A new request: list the operations once its text is shown.
        self._rows_loaded = False     # The tabs reflect the saved requests at least once.

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
        if row is None or area.read_only:
            return
        self.editor.say("Editing…" if self.editor_dirty() else
                        "Choose an operation" if row["request"] == {} else "Saved")

    def on_text_area_changed(self, event):
        """Edits are saved on their own, a moment after typing stops."""
        event.stop()
        self.show_editor_state()
        if self._autosave is not None:
            self._autosave.stop()
        self._autosave = self.set_timer(AUTOSAVE_DELAY, self.autosave) if self.editor_dirty() else None

    def autosave(self):
        self._autosave = None
        if self.editor_dirty():
            self.save_editor(quiet=True)

    def flush_editor(self):
        """Save typing that the automatic save has not reached yet, e.g. when noxen is closing."""
        try:
            if self.selected() is not None and self.editor_dirty():
                self.save_editor(quiet=True)
        except Exception:
            pass  # The pane may already be coming down; an unsaved edit must not block closing.

    def save_editor(self, quiet=False):
        """Save the JSON on screen. Returns the saved request, or None if it is not valid.

        `quiet` is the automatic save: text that is not valid yet is normal
        while typing, so it is only noted, without moving the cursor.
        """
        row, area, key = self.selected(), self.editor.area, self._editor_key
        if row is None or key is None or key[0] not in (row["id"], "run"):
            return None  # The editor has not caught up with the selected tab yet: nothing here belongs to it.
        if area.read_only or not self.editor_dirty():
            return row
        try:
            # Based on the revision the text was loaded from, so a change made elsewhere is a conflict.
            saved = self.service.save_request(row["name"], sender_json.parse(area.text, area.folds),
                                              row["id"], key[1])
        except (ValueError, OSError, sqlite3.Error) as error:
            # Text that is not valid waits for the next edit; a storage failure is tried again.
            self._retry_save = not isinstance(error, ValueError)
            if quiet:
                self.editor.say(f"Not saved yet · {error}")
                return None
            self.editor.say(str(error), error=True)
            if (line := re.match(r"Line (\d+), column (\d+)", str(error))) and not area.folds:
                area.move_cursor((int(line.group(1)) - 1, int(line.group(2)) - 1))
            area.focus()
            return None
        self._editor_baseline = area.full_text()
        self._editor_key = (saved["id"], saved["revision"])
        self._requests = [dict(r, revision=saved["revision"], request=saved["request"]) if r["id"] == saved["id"] else r
                          for r in self._requests]
        self.show_editor_state()
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
            self.editor.say(f"As sent in run #{run['id']} · read only")
        else:
            key = (row["id"], row["revision"])
            if key != self._editor_key and self._editor_key is not None and self._editor_key[0] == row["id"]:
                # Changed elsewhere (e.g. over MCP): show that. Text here that was never valid is dropped.
                self._drafts.pop(row["id"], None)
                self._editor_key, self._editor_baseline = None, self.editor.area.full_text()
            if key != self._editor_key:
                self.stash_draft()
                saved_text = request_text(row["request"])
                # A draft keeps the revision it was written against, so a later change still conflicts.
                text, folds, revision, baseline = self._drafts.pop(row["id"], (saved_text, {}, row["revision"], saved_text))
                self._editor_key, self._editor_baseline = (row["id"], revision), baseline
                area.read_only = False
                area.load(text, folds)
                if self._suggest_on_load == row["id"] and text == NEW_REQUEST_TEXT:
                    area.move_cursor(area.location(NEW_REQUEST_TEXT.index('""') + 1))
                    area.focus()
                    self.call_after_refresh(area.show_completions, True)
            if self._suggest_on_load == row["id"]:
                self._suggest_on_load = None
        self.show_editor_state()

    def stash_draft(self):
        """Keep what the automatic save cannot: text that is not valid yet, and which blocks are folded."""
        key, area = self._editor_key, self.editor.area
        if key is not None and key[0] != "run" and (self.editor_dirty() or area.folds):
            self._drafts[key[0]] = (area.text, dict(area.folds), key[1], self._editor_baseline)

    def select_request(self, request_id):
        if request_id != self._selected_id:
            if self.selected() is not None and self.editor_dirty():
                self.save_editor(quiet=True)  # Leave nothing valid unsaved behind; invalid text stays a draft.
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
            or row is None or row["request"] == {}
        )
        self.query_one("#sender_cancel_run", Button).disabled = not (
            row is not None and status["active_run"] is not None and status["active_run"] in self._run_ids[:1]
            and row["request"].get("operation") in ("query", "openFileDescriptor"))
        if self._retry_save and self._autosave is None:
            self._retry_save = False
            self._autosave = self.set_timer(AUTOSAVE_DELAY, self.autosave)
        if self._rows_loaded and not self._requests and self.is_on_screen:
            self.ensure_request()  # Shown with nothing to edit, e.g. a new project or after MCP removed the last one.
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
        if self._signature != signature or not self.query("#sender_run_older"):
            return  # Superseded, or the pane was closed while the records were read.
        self._requests, self._run_ids, self._rows_loaded = requests, run_ids, True
        if self._run_id not in run_ids:
            self._run_id = None
        position = run_ids.index(run_id) if run_ids else 0
        self.query_one("#sender_run_older", Button).disabled = position >= len(run_ids) - 1
        self.query_one("#sender_run_newer", Button).disabled = position == 0
        self.query_one("#sender_result_title", Label).update(
            Text(f"Result · run {len(run_ids) - position} of {len(run_ids)}" if run_ids else "Result"))
        await self.show_tabs()
        row = self.selected()
        # An earlier run is shown with the request exactly as it was sent.
        self.show_request_json(row, run)
        same_revision = run is not None and (self._run_id is not None or run["revision"] == row["revision"])
        shown = (row and row["id"], run and (run["id"], run["state"], run.get("receivedAt")), same_revision)
        if shown != self._result_shown:
            # An automatic save alone leaves the result as it is, scroll position included.
            self._result_shown = shown
            result_log = self.query_one("#sender_run_detail", RichLog)
            result_log.clear()
            if row is not None and run is None:
                result_log.write(Text("Not sent yet.", style="dim"))
            elif row is not None:
                result_log.write(render_sender_detail(
                    run, current_revision=run["revision"] if same_revision else row["revision"]))
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
        return str(max([int(name) for name in names if name.isdecimal() and len(name) <= 9], default=0) + 1)

    def receive_request(self, request):
        """Add a request prepared in another tab and select it, named with the next number like +.

        One that is not valid as captured is still shown, as unsaved text over
        an empty request, so it can be repaired here instead of being altered.
        """
        name = self.next_name()
        try:
            saved = self.service.save_request(name, request)
        except SenderError as error:
            saved = self.service.save_request(name, {})
            self._drafts[saved["id"]] = (sender_json.format_request(request), {}, saved["revision"], NEW_REQUEST_TEXT)
            self.notify(f"{error}. It is in Sender as request {name}, unsaved: fix it there.", severity="warning")
        else:
            self.notify(f"Sent to Sender as request {name}")
        self.select_request(saved["id"])

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

    def open_tab_menu(self, request_id, x, y):
        self.select_request(request_id)
        def chosen(action):
            row = self.service.db.sender_request(request_id) if action else None
            if row is None:
                return
            try:
                if action == "rename":
                    def renamed(name):
                        if name is None or name == row["name"]:
                            return
                        try:
                            current = self.service.db.sender_request(request_id)
                            saved = self.service.save_request(name, current["request"], request_id, current["revision"])
                            # Only the name changed: text being typed is still based on the same request.
                            if self._editor_key == (request_id, current["revision"]):
                                self._editor_key = (request_id, saved["revision"])
                            draft = self._drafts.get(request_id)
                            if draft is not None and draft[2] == current["revision"]:
                                self._drafts[request_id] = (draft[0], draft[1], saved["revision"], draft[3])
                            self.refresh_sender()
                        except Exception as error:
                            self.notify(str(error), severity="error")
                    self.app.push_screen(SenderRenameModal(row["name"]), renamed)
                elif action == "duplicate":
                    name = self.next_name() if row["name"].isdecimal() else (row["name"] + " copy")[:200]
                    self.select_request(self.service.save_request(name, row["request"])["id"])
                elif action == "close":
                    self.remove_requests([row])
                elif action in closing:
                    self.confirm_remove(closing[action])
                self.refresh_sender()
            except Exception as error:
                self.notify(str(error), severity="error")
        order = [row["id"] for row in self._requests]
        position = order.index(request_id) if request_id in order else 0
        closing = {"close_other": order[:position] + order[position + 1:],
                   "close_left": order[:position], "close_right": order[position + 1:]}
        options = [("Rename", "rename"), ("Duplicate", "duplicate"), ("Close", "close")]
        options += [(label, key) for label, key in (("Close other tabs", "close_other"),
                    ("Close tabs to the left", "close_left"), ("Close tabs to the right", "close_right"))
                    if closing[key]]
        self.app.push_screen(SenderTabMenu(x, y, options), chosen)

    def remove_requests(self, rows):
        """Remove saved requests, with any unsaved text of theirs. Closing the last one leaves a new empty one."""
        for row in rows:
            self.service.remove_request(row["id"], row["revision"])
            self._drafts.pop(row["id"], None)
            if self._editor_key is not None and self._editor_key[0] == row["id"]:
                self._editor_key, self._editor_baseline = None, self.editor.area.full_text()
        if not self.service.db.sender_requests():
            self._suggest_on_load = self.ensure_request()["id"]
            self.select_request(self._suggest_on_load)

    def ensure_request(self):
        """There is always a request on screen: an empty one is created when none is left."""
        current = self.service.db.sender_requests()  # Read again: one may have been saved meanwhile.
        if not current:
            self.service.save_request(self.next_name(), {})
            current = self.service.db.sender_requests()
        return min(current, key=lambda row: row["number"])

    def confirm_remove(self, request_ids):
        """Closing several tabs deletes their requests, so it is confirmed first."""
        names = [row["name"] for row in self._requests if row["id"] in request_ids]
        shown = ", ".join(names[:8]) + (f" and {len(names) - 8} more" if len(names) > 8 else "")
        def answered(confirmed):
            if not confirmed:
                return
            try:
                # Read again: a request may have been saved since the menu opened.
                self.remove_requests([row for row in self.service.db.sender_requests() if row["id"] in request_ids])
            except Exception as error:
                self.notify(str(error), severity="error")
            self.refresh_sender()
        message = (f"Close tab {shown}?\n\nIts request is deleted." if len(names) == 1 else
                   f"Close {len(names)} tabs: {shown}?\n\nTheir requests are deleted.")
        self.app.push_screen(RecordingDialog(message + " This cannot be undone.", "Close"), answered)

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
                saved = self.service.save_request(self.next_name(), {})
                self._suggest_on_load = saved["id"]
                self.select_request(saved["id"])
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
                if row["request"] == {}:
                    raise ValueError("Choose an operation first")
                if row["request"]["operation"] == "startActivity":
                    self._checking_activity_send = True
                    self.send_activity(row, self.service.token)
                else:
                    self.dispatch_request(row, self.service.token)
            self.refresh_sender()
        except Exception as error:
            self.notify(str(error), severity="error")
