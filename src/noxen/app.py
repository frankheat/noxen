import logging
import os
import re
import sys
import threading
from datetime import datetime
from importlib.metadata import version as pkg_version, PackageNotFoundError

from textual import events
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Vertical, Horizontal, VerticalScroll
from textual.widgets import (
    Button, DataTable, Footer, Input, Label,
    OptionList, RichLog, Rule, Select, Static, Switch, TabbedContent, TabPane,
)
from textual.binding import Binding

from noxen.commands import (
    CommandSuggester,
    HELP_MENU,
    HELP_MENU_HISTORY,
    HISTORY_COMPLETIONS,
    INTERCEPT_COMPLETIONS,
    completion_fill_from_prompt,
    format_completion_option,
    matching_completions,
    parse_clear_command,
    parse_command,
    parse_export_command,
    parse_filter_command,
    parse_intent_command,
    parse_intercept_command,
    parse_save_command,
    parse_stack_command,
    parse_theme_command,
    resolve_submitted_command,
)
from noxen.db import ProjectDB
from noxen.exporting import (
    history_entries_label,
    write_filter_export,
    write_history_export,
)
from noxen.filters import FilterManager
from noxen.frida_devices import prefer_non_local_devices
from noxen.frida_session import FridaSession, SessionConfig
from noxen.intent_mods import (
    JAVA_TYPE_TO_SIMPLE,
    VALID_EXTRA_TYPES,
    apply_mods_to_entry,
    java_type_display,
    parse_flag_value,
    parse_intent_mod_command,
)
from noxen.logging_ui import is_debug_log, log_debug, log_error, log_info, log_success, log_warning
from noxen.modals import (
    ColumnSelectModal,
    FileBrowserModal,
    HelpModal,
    FilterModal,
    StackModal,
)
from noxen.rendering import (
    HISTORY_OUTCOME_CELL,
    entry_to_filter_context,
    filter_sort_history_entries,
    history_row_values,
    payload_to_history_entry,
    render_intent_detail,
)
from noxen.settings import load_settings, save_settings
from noxen.system_server_session import SystemServerConfig, SystemServerSession
from noxen.textual_compat import SELECT_EMPTY, is_select_empty

_HISTORY_COLUMNS = [
    ("id",        "#"),
    ("outcome",   "→/✗"),
    ("time",      "Time"),
    ("method",    "Method"),
    ("class",     "Class"),
    ("component", "Component"),
    ("action",    "Action"),
    ("extras",    "Extras"),
]

LOGGER = logging.getLogger(__name__)

MIN_PANEL_HEIGHT = 3
MIN_HISTORY_DETAIL_HEIGHT = 3
MAX_COMMAND_OUTPUT_HEIGHT = 20
INTERCEPT_COMMAND_OUTPUT_HEIGHT = 7
HISTORY_COMMAND_OUTPUT_HEIGHT = 4
INTERCEPT_ACTION_BUTTON_CLASSES = (
    "intercept-on",
    "intercept-off",
    "forward-ready",
    "drop-ready",
    "edit-ready",
)


def clamp_height(value: int, minimum: int, maximum: int | None = None) -> int:
    value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def max_primary_panel_height(primary_height: int, secondary_height: int, secondary_minimum: int) -> int:
    return clamp_height(primary_height + secondary_height - secondary_minimum, MIN_PANEL_HEIGHT)


class HomeLogo(Static):
    # "coder mini" font — 3 rows × 29 chars
    _ART = [
        "████▄ ▄███▄ ██ ██ ▄█▀█▄ ████▄",
        "██ ██ ██ ██  ███  ██▄█▀ ██ ██",
        "██ ██ ▀███▀ ██ ██ ▀█▄▄▄ ██ ██",
    ]

    def on_mount(self) -> None:
        self._render_brand()

    def on_resize(self) -> None:
        self._render_brand()

    @staticmethod
    def _lerp_color(t: float) -> str:
        r = int(0xC9 + (0x26 - 0xC9) * t)
        g = int(0x4A + (0xA3 - 0x4A) * t)
        b = int(0x8A + (0x68 - 0x8A) * t)
        return f"#{r:02x}{g:02x}{b:02x}"

    def _render_brand(self) -> None:
        panel_w = self.size.width
        scale = max(1, panel_w // (len(self._ART[0]) + 4))
        top_pad = self.app.size.height // 4
        n = len(self._ART)

        lines = [""] * top_pad
        for i, row in enumerate(self._ART):
            color = self._lerp_color(i / max(1, n - 1))
            for sub in range(scale):
                scaled = ''.join(
                    '█' * scale if c == '█'
                    else ('█' if sub == scale - 1 else ' ') * scale if c == '▄'
                    else ('█' if sub == 0 else ' ') * scale if c == '▀'
                    else c * scale
                    for c in row
                )
                lines.append(f"[bold {color}]{scaled}[/bold {color}]")
        self.update("\n".join(lines))


class HomeInfo(Static):
    def on_mount(self) -> None:
        self.refresh_info()

    def refresh_info(self) -> None:
        try:
            noxen_ver = pkg_version("noxen")
        except PackageNotFoundError:
            noxen_ver = "dev"
        try:
            frida_ver = pkg_version("frida")
        except PackageNotFoundError:
            frida_ver = "—"
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

        db = getattr(self.app, "db", None)
        if db and os.path.exists(db.path):
            db_name = os.path.basename(db.path)
            created = datetime.fromtimestamp(os.path.getctime(db.path)).strftime("%Y-%m-%d %H:%M")
            modified = datetime.fromtimestamp(os.path.getmtime(db.path)).strftime("%Y-%m-%d %H:%M")
        else:
            db_name = "—"
            created = "—"
            modified = "—"

        self.update(
            f"[dim]noxen[/dim]    [#26a368]{noxen_ver}[/#26a368]\n"
            f"[dim]frida[/dim]    [#26a368]{frida_ver}[/#26a368]\n"
            f"[dim]python[/dim]   [#26a368]{py_ver}[/#26a368]\n"
            f"\n"
            f"[dim]project[/dim]  {db_name}\n"
            f"[dim]created[/dim]  {created}\n"
            f"[dim]modified[/dim] {modified}"
        )


class NoxenApp(App):
    TITLE = "noxen"
    CSS_PATH = "noxen.tcss"
    ENABLE_COMMAND_PALETTE = False

    BINDINGS = [
        Binding("ctrl+c", "quit", show=False, priority=True),
        Binding("ctrl+q", "quit", "Quit", priority=True),
        Binding("ctrl+l", "clear_log", "Clear", priority=True),
        Binding("alt+up", "resize_panel_up", "▲", show=True),
        Binding("alt+down", "resize_panel_down", "▼", show=True),
        Binding("ctrl+b", "toggle_command_bar", "Command area", show=True, priority=True),
    ]

    def __init__(self, cli_args):
        super().__init__()
        self._skip_startup_device_scan = bool(getattr(cli_args, "skip_device_scan", False))
        self._session_config: SessionConfig | None = None
        self._settings = load_settings()
        self.show_stack = self._settings["stack"]
        self.stack_depth = self._settings["stack_depth"]
        self._all_intents = []
        self._history_refresh_pending = False
        self._pending_append: list = []
        self._sort_column: str | None = "id"
        self._sort_reverse: bool = True
        self._history_visible_cols: set[str] = {key for key, _ in _HISTORY_COLUMNS}
        self._history_show_stack = False
        self._history_stack_depth: int = self._settings["stack_depth"]
        self._history_selected_entry: dict | None = None
        self._intercept_mode = self._settings["intercept"]
        self._current_intercept_id: int | None = None
        self._current_decision_id: str | None = None
        self._current_intercepted_entry: dict | None = None
        self._edit_mode = False
        self._edit_extra_counter = 0
        self._edit_extra_rows: dict = {}
        self._edit_removed_keys: set = set()
        self._edit_cat_counter = 0
        self._edit_cat_rows: dict = {}
        self._edit_removed_categories: set = set()
        self._staged_mods: list = []
        self._active_tab = "tab_intercept"
        self._startup_messages = []
        self._history_search_text = ""
        self._history_table_height: int | None = None
        self._history_cmd_height = HISTORY_COMMAND_OUTPUT_HEIGHT
        self._intercept_cmd_height = INTERCEPT_COMMAND_OUTPUT_HEIGHT
        self._intercept_command_bar_visible = self._settings["intercept_command_bar"]
        self._history_command_bar_visible = self._settings["history_command_bar"]
        self._home_devices = []
        self._connect_scan_generation = 0
        self._session_device_id = ""
        self._system_anr_bypass_enabled = False
        self._log_verbose = False
        self._log_entries: list[str] = []
        self.system_server_session: SystemServerSession | None = None
        self.frida_session = None
        self.db, self._all_intents = self._init_project(cli_args)
        saved_cols = self.db.load_history_columns()
        if saved_cols is not None:
            self._history_visible_cols = set(saved_cols)
        self.filter_manager = FilterManager.from_saved(self.db.load_intercept_filters())
        self._history_filter_manager = FilterManager.from_saved(self.db.load_history_filters())

    def _init_project(self, cli_args) -> tuple:
        """Resolve DB path, open or create the project, return (ProjectDB, intents)."""
        project = getattr(cli_args, "project", None)
        new_project = getattr(cli_args, "new_project", None)

        if project:
            path = project if project.endswith(".noxen") else project + ".noxen"
            db = ProjectDB(path)
            try:
                intents = db.open_existing()
                for warning in db.load_warnings:
                    self._startup_messages.append(log_warning(warning, "project"))
                self._startup_messages.append(
                    log_success(f"Opened project '{db.name or path}' ({len(intents)} intent(s))", "project")
                )
                return db, intents
            except FileNotFoundError as e:
                self._startup_messages.append(log_error(str(e), "project"))
                return db, []

        if new_project:
            path = new_project if new_project.endswith(".noxen") else new_project + ".noxen"
            db = ProjectDB(path)
            try:
                db.create(new_project)
                self._startup_messages.append(log_success(f"Created project '{new_project}' at {path}", "project"))
            except FileExistsError as e:
                self._startup_messages.append(log_error(str(e), "project"))
            return db, []

        # Auto-create with timestamp
        name = datetime.now().strftime("project_%Y%m%d_%H%M%S")
        path = name + ".noxen"
        db = ProjectDB(path)
        db.create(name)
        self._startup_messages.append(log_debug(f"Created project {path}", "project"))
        return db, []

    def _init_session(self, config: SessionConfig):
        self._session_config = config
        self.frida_session = FridaSession(
            config,
            filter_manager=self.filter_manager,
            log_cb=self.write_log,
            intercept_cb=self.set_intercept_state,
            get_stack=lambda: (self.show_stack, self.stack_depth),
            history_cb=self._on_history_intent,
            outcome_cb=self._update_outcome,
            intercept_log_cb=self._on_intercept_display,
            initial_intercept=self._intercept_mode,
            hold_start_cb=self._on_hold_start,
            hold_end_cb=self._on_hold_end,
        )

    def action_clear_log(self):
        if self._active_tab == "tab_history":
            self.action_clear_history()
        elif self._active_tab == "tab_log":
            self._log_entries.clear()
            try:
                self.query_one("#log_output", RichLog).clear()
            except Exception:
                pass

    def action_toggle_theme(self):
        if self.theme == "textual-dark":
            self.theme = "textual-light"
        else:
            self.theme = "textual-dark"


    def _enter_edit_mode(self):
        if not self._current_intercepted_entry or self._edit_mode:
            return
        entry = self._current_intercepted_entry
        info = entry.get("intent", {}) or {}

        self.query_one("#ef_action", Input).value = info.get("action", "") or ""
        self.query_one("#ef_data", Input).value = info.get("data", "") or ""

        self.query_one("#ef_categories").remove_children()
        self._edit_cat_rows = {}
        self._edit_removed_categories = set()
        for cat in (info.get("categories", []) or []):
            self._add_edit_category_row(cat, is_new=False)

        self.query_one("#ef_extras").remove_children()
        self._edit_extra_rows = {}
        self._edit_removed_keys = set()
        for key, extra in (info.get("extras", {}) or {}).items():
            java_type = extra.get("type") or ""
            simple_type = JAVA_TYPE_TO_SIMPLE.get(java_type)
            self._add_edit_extra_row(key, simple_type, str(extra.get("value", "") or ""), is_new=False, java_type=java_type)

        flags_val = info.get("flags") or 0
        try:
            self.query_one("#ef_flags", Input).value = hex(int(flags_val)) if flags_val else ""
        except Exception:
            self.query_one("#ef_flags", Input).value = ""

        self.query_one("#intercept_output").display = False
        ef = self.query_one("#edit_form")
        ef.display = True
        ef.scroll_home(animate=False)
        self.query_one("#btn_edit").disabled = True
        self._edit_mode = True

    def _exit_edit_mode(self):
        if not self._edit_mode:
            return
        self.query_one("#intercept_output").display = True
        self.query_one("#edit_form").display = False
        self._edit_mode = False
        try:
            still_intercepted = "intercepted" in self.query_one("#intercept_input_bar").classes
            self.query_one("#btn_edit").disabled = not still_intercepted
            if still_intercepted:
                self.query_one("#btn_forward", Button).disabled = False
                self.query_one("#btn_drop", Button).disabled = False
        except Exception:
            pass

    def _add_edit_category_row(self, value: str, is_new: bool):
        self._edit_cat_counter += 1
        n = self._edit_cat_counter
        self._edit_cat_rows[n] = {"orig_value": value if not is_new else None, "is_new": is_new}
        row = Horizontal(
            Input(id=f"ef_cv_{n}", value=value,
                  placeholder="e.g. android.intent.category.DEFAULT",
                  classes="ef_cat_input"),
            Button("✕", id=f"ef_crm_{n}", classes="ef_x_rm"),
            id=f"ef_cat_{n}", classes="ef_cat_row",
        )
        self.query_one("#ef_categories").mount(row)

    def _add_edit_extra_row(self, key: str, simple_type, value: str, is_new: bool, java_type: str = ""):
        self._edit_extra_counter += 1
        n = self._edit_extra_counter
        self._edit_extra_rows[n] = {"key": key, "is_new": is_new, "type": simple_type or "string"}

        if is_new:
            type_opts = [(t, t) for t in sorted(VALID_EXTRA_TYPES)]
            row = Horizontal(
                Input(id=f"ef_xk_{n}", placeholder="key", classes="ef_x_key_input"),
                Select(type_opts, id=f"ef_xt_{n}", value="string",
                       allow_blank=False, classes="ef_x_type_select"),
                Input(id=f"ef_xv_{n}", placeholder="value"),
                Button("✕", id=f"ef_xrm_{n}", classes="ef_x_rm"),
                id=f"ef_x_{n}", classes="ef_x_row",
            )
        else:
            editable = simple_type is not None
            type_label = java_type_display(java_type)
            row = Horizontal(
                Label(key, classes="ef_x_key_label"),
                Label(type_label, classes="ef_x_type_label"),
                Input(id=f"ef_xv_{n}", value=value, disabled=not editable),
                Button("✕", id=f"ef_xrm_{n}", classes="ef_x_rm"),
                id=f"ef_x_{n}", classes="ef_x_row",
            )

        self.query_one("#ef_extras").mount(row)

    def _collect_edit_mods(self) -> list:
        entry = self._current_intercepted_entry
        info = entry.get("intent", {}) or {}
        mods = []

        new_action = self.query_one("#ef_action", Input).value.strip()
        if new_action != (info.get("action", "") or ""):
            mods.append(("action", "", new_action, ""))

        new_data = self.query_one("#ef_data", Input).value.strip()
        if new_data != (info.get("data", "") or ""):
            mods.append(("data", "", new_data, ""))

        for cat in self._edit_removed_categories:
            mods.append(("cat_rem", "", cat, ""))

        for n, row_info in self._edit_cat_rows.items():
            try:
                val = self.query_one(f"#ef_cv_{n}", Input).value.strip()
                orig = row_info["orig_value"]
                if row_info["is_new"]:
                    if val:
                        mods.append(("cat_add", "", val, ""))
                elif val != (orig or ""):
                    mods.append(("cat_rem", "", orig, ""))
                    if val:
                        mods.append(("cat_add", "", val, ""))
            except Exception:
                pass

        for key in self._edit_removed_keys:
            mods.append(("extra_rem", key, "", ""))

        orig_extras = info.get("extras", {}) or {}
        for n, row_info in self._edit_extra_rows.items():
            if row_info["is_new"] or row_info["key"] in self._edit_removed_keys:
                continue
            try:
                new_val = self.query_one(f"#ef_xv_{n}", Input).value
                orig_val = str(orig_extras.get(row_info["key"], {}).get("value", "") or "")
                if new_val != orig_val:
                    mods.append(("extra_rem", row_info["key"], "", ""))
                    mods.append(("extra_add", row_info["key"], new_val, row_info["type"]))
            except Exception:
                pass

        for n, row_info in self._edit_extra_rows.items():
            if not row_info["is_new"]:
                continue
            try:
                key = self.query_one(f"#ef_xk_{n}", Input).value.strip()
                type_val = str(self.query_one(f"#ef_xt_{n}", Select).value)
                val = self.query_one(f"#ef_xv_{n}", Input).value
                if key:
                    mods.append(("extra_add", key, val, type_val))
            except Exception:
                pass

        old_flags = parse_flag_value(info.get("flags") or 0) or 0
        try:
            new_flags_str = self.query_one("#ef_flags", Input).value.strip()
            new_flags = parse_flag_value(new_flags_str) if new_flags_str else 0
        except Exception:
            new_flags = old_flags
        if new_flags is not None and new_flags != old_flags:
            if old_flags:
                mods.append(("flag_rem", "", str(old_flags), ""))
            if new_flags:
                mods.append(("flag_add", "", str(new_flags), ""))

        return mods

    def _forward_from_edit_mode(self):
        """Main-thread helper: collect mods, exit edit mode, then forward."""
        if not self._edit_mode:
            return
        mods = self._collect_edit_mods()
        self._exit_edit_mode()
        self._apply_mods_and_forward_worker(mods)

    @work(thread=True)
    def _apply_mods_and_forward_worker(self, mods: list):
        try:
            if not self.frida_session or not self.frida_session.is_ready():
                self.write_cmd("[red]Session not ready[/red]")
                return
            decision_id = self._current_decision_id
            intent_id = self._current_intercept_id
            resolved = self._current_intercepted_entry
            all_mods = list(self._staged_mods) + list(mods)
            for mod_type, key, val, extra_type in mods:
                if not self.frida_session.stage_mod(mod_type, key, val, extra_type, decision_id):
                    self.write_cmd("[red]No matching intent blocked to modify[/red]")
                    return
            if not self.frida_session.forward(decision_id):
                self.write_cmd("[red]No matching intent blocked to forward[/red]")
                return
            self.set_intercept_state(False)
            self._finalize_forward(intent_id, resolved, all_mods)
        except Exception as e:
            self.write_cmd(f"[red]Modify & forward failed: {e}[/red]")

    def _stage_current_mod(self, mod_type: str, key: str, val: str, extra_type: str = "") -> None:
        if self._current_intercepted_entry is None or self._current_intercept_id is None:
            self.write_cmd("[red]No intent blocked to modify[/red]")
            return
        if not self.frida_session.stage_mod(mod_type, key, val, extra_type, self._current_decision_id):
            self.write_cmd("[red]No matching intent blocked to modify[/red]")
            return
        self._staged_mods.append((mod_type, key, val, extra_type))

    def _finalize_forward(self, intent_id: int | None, resolved_entry: dict | None, mods: list) -> None:
        entry = resolved_entry
        if entry is None and intent_id is not None:
            entry = next((e for e in self._all_intents if e["id"] == intent_id), None)

        if entry is not None and mods:
            apply_mods_to_entry(entry, mods)

        outcome = "modified_forwarded" if mods else "forwarded"
        self._update_outcome(intent_id, outcome)
        if mods and self.db and intent_id and entry and entry.get("original_intent") is not None:
            self.db.update_modified_intent(intent_id, entry["original_intent"], entry["intent"])
        self._staged_mods.clear()
        self.call_from_thread(lambda e=resolved_entry: self._clear_intercept_output(e))

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "home_refresh":
            self._populate_home_devices()
            return
        elif event.button.id == "home_target_refresh":
            self._populate_target_apps()
            return
        elif event.button.id == "home_btn":
            self._try_connect()
            return
        elif event.button.id == "home_disconnect":
            self._do_disconnect()
            return
        elif event.button.id == "home_hooks_browse":
            self.app.push_screen(
                FileBrowserModal("Select custom hooks file"),
                lambda p: self._set_path_input("home_hooks_path", p),
            )
            return
        elif event.button.id == "home_script_browse":
            self.app.push_screen(
                FileBrowserModal("Select extra script file"),
                lambda p: self._set_path_input("home_script_path", p),
            )
            return
        elif event.button.id in ("home_hooks_clear", "home_script_clear"):
            target = "home_hooks_path" if event.button.id == "home_hooks_clear" else "home_script_path"
            try:
                self.query_one(f"#{target}", Input).value = ""
            except Exception:
                pass
            return
        elif event.button.id == "intercept_toggle":
            self.process_command_worker("/intercept off" if self._intercept_mode else "/intercept on")
        elif event.button.id == "btn_forward":
            if self._edit_mode:
                self._forward_from_edit_mode()
                return
            self.process_command_worker("forward")
        elif event.button.id == "btn_drop":
            self.process_command_worker("drop")
        elif event.button.id == "btn_edit":
            self._enter_edit_mode()
            return
        elif event.button.id == "ef_add_extra":
            self._add_edit_extra_row("", None, "", is_new=True)
            return
        elif event.button.id == "ef_add_cat":
            self._add_edit_category_row("", is_new=True)
            return
        elif (event.button.id or "").startswith("ef_crm_"):
            n = int(event.button.id.split("_")[-1])
            row_info = self._edit_cat_rows.pop(n, None)
            if row_info and not row_info["is_new"] and row_info["orig_value"]:
                self._edit_removed_categories.add(row_info["orig_value"])
            try:
                self.query_one(f"#ef_cat_{n}").remove()
            except Exception:
                pass
            return
        elif (event.button.id or "").startswith("ef_xrm_"):
            n = int(event.button.id.split("_")[-1])
            row_info = self._edit_extra_rows.pop(n, None)
            if row_info and not row_info["is_new"]:
                self._edit_removed_keys.add(row_info["key"])
            try:
                self.query_one(f"#ef_x_{n}").remove()
            except Exception:
                pass
            return
        elif event.button.id == "btn_intercept_filters":
            self.push_screen(FilterModal(
                self.filter_manager,
                on_filters_changed=self._on_intercept_filters_changed,
                title="Intercept Filters",
            ))
            return
        elif event.button.id == "btn_history_filters":
            self.push_screen(FilterModal(
                self._history_filter_manager,
                on_filters_changed=self._on_history_filters_changed,
                title="History Filters",
            ))
            return
        elif event.button.id == "btn_columns":
            self.push_screen(ColumnSelectModal(
                self._history_visible_cols,
                on_changed=self._on_columns_changed,
                columns=_HISTORY_COLUMNS,
            ))
            return
        elif event.button.id == "btn_intercept_stack":
            def _on_intercept_stack_confirm(show: bool, depth: int):
                self.show_stack = show
                self.stack_depth = depth
                if self._current_intercepted_entry is not None:
                    try:
                        intercept_output = self.query_one("#intercept_output", RichLog)
                        intercept_output.clear()
                        intercept_output.write(render_intent_detail(
                            self._current_intercepted_entry,
                            show_stack=show,
                            stack_depth=depth,
                        ))
                    except Exception:
                        pass
            self.push_screen(StackModal(self.show_stack, self.stack_depth, _on_intercept_stack_confirm))
            return
        elif event.button.id == "btn_history_stack":
            def _on_stack_confirm(show: bool, depth: int):
                self._history_show_stack = show
                self._history_stack_depth = depth
                self._refresh_history_detail()
            self.push_screen(StackModal(self._history_show_stack, self._history_stack_depth, _on_stack_confirm))
            return
        elif event.button.id == "settings_save":
            try:
                val = int(self.query_one("#settings_depth_input", Input).value.strip())
                if val < 1:
                    raise ValueError
                self._settings["stack_depth"] = val
                self.query_one("#settings_depth_error", Label).update("")
            except ValueError:
                self.query_one("#settings_depth_error", Label).update("Enter a positive integer")
                return
            self._settings["intercept"] = self.query_one("#settings_intercept", Switch).value
            self._settings["stack"] = self.query_one("#settings_stack", Switch).value
            save_settings(self._settings)
            self.notify("Settings saved", severity="information", timeout=2)
            return
        self.query_one("#intercept_command_input", Input).focus()

    def update_intercept_button(self, enabled: bool):
        self._intercept_mode = enabled

        def _do():
            try:
                btn = self.query_one("#intercept_toggle", Button)
                btn.label = "Intercept on" if enabled else "Intercept off"
                self._set_intercept_action_button_classes(
                    btn,
                    "intercept-on" if enabled else "intercept-off",
                )
            except Exception:
                pass

        if threading.current_thread() is threading.main_thread():
            _do()
        else:
            self.call_from_thread(_do)

    def _set_intercept_action_button_classes(self, button: Button, *classes: str) -> None:
        for class_name in INTERCEPT_ACTION_BUTTON_CLASSES:
            button.remove_class(class_name)
        for class_name in classes:
            button.add_class(class_name)

    def _set_widget_display(self, selector: str, visible: bool) -> None:
        try:
            self.query_one(selector).display = visible
        except Exception:
            LOGGER.debug("Unable to set display for %s", selector, exc_info=True)

    def _save_command_bar_settings(self) -> None:
        self._settings["intercept_command_bar"] = self._intercept_command_bar_visible
        self._settings["history_command_bar"] = self._history_command_bar_visible
        try:
            save_settings(self._settings)
        except OSError:
            LOGGER.warning("Unable to save command bar settings", exc_info=True)
            self.notify("Unable to save command bar settings", severity="warning", timeout=3)

    def _apply_intercept_command_bar_visibility(self) -> None:
        visible = self._intercept_command_bar_visible
        self._set_widget_display("#intercept_cmd_output", visible)
        self._set_widget_display("#intercept_input_wrapper", visible)
        self._set_widget_display("#intercept_cmd_suggestions", False)
        if visible:
            self.call_after_refresh(self._clamp_intercept_command_output_to_available_space)
        elif getattr(self.focused, "id", None) in ("intercept_command_input", "intercept_cmd_output"):
            self._focus_intercept_main_panel()

    def _apply_history_command_bar_visibility(self) -> None:
        visible = self._history_command_bar_visible and self._active_tab == "tab_history"
        self._set_widget_display("#history_bar_container", visible)
        self._set_widget_display("#history_cmd_suggestions", False)
        if self._active_tab == "tab_history":
            self.call_after_refresh(self._clamp_history_table_to_available_space)
            if not visible and getattr(self.focused, "id", None) in ("history_command_input", "history_cmd_output"):
                self._focus_history_main_panel()

    def _apply_command_bar_visibility(self) -> None:
        self._apply_intercept_command_bar_visibility()
        self._apply_history_command_bar_visibility()

    def _toggle_intercept_command_bar(self) -> None:
        self._intercept_command_bar_visible = not self._intercept_command_bar_visible
        self._apply_intercept_command_bar_visibility()
        self._save_command_bar_settings()

    def _toggle_history_command_bar(self) -> None:
        self._history_command_bar_visible = not self._history_command_bar_visible
        self._apply_history_command_bar_visibility()
        self._save_command_bar_settings()

    def _focus_intercept_main_panel(self) -> None:
        try:
            self.query_one("#intercept_output", RichLog).focus()
        except Exception:
            LOGGER.debug("Unable to focus intercept intercept_output", exc_info=True)

    def _focus_history_main_panel(self) -> None:
        try:
            self.query_one("#history_table", DataTable).focus()
        except Exception:
            LOGGER.debug("Unable to focus history table", exc_info=True)

    def _focus_intercept_default(self) -> None:
        try:
            if self._intercept_command_bar_visible:
                self.query_one("#intercept_command_input", Input).focus()
            else:
                self._focus_intercept_main_panel()
        except Exception:
            LOGGER.debug("Unable to focus intercept default widget", exc_info=True)

    def compose(self) -> ComposeResult:
        yield Horizontal(Label("", id="session_info"), id="session_bar")
        with TabbedContent(id="main_tabs"):
            with TabPane(" Home ", id="tab_home"):
                with Horizontal(id="home_split"):
                    with Vertical(id="home_sidebar"):
                        yield HomeLogo("", id="home_logo", markup=True)
                        yield HomeInfo("", id="home_info", markup=True)
                    with VerticalScroll(id="home_form"):
                        yield Label("Connect to App", id="home_title")
                        yield Rule()

                        with Horizontal(classes="connect_row"):
                            yield Label("Device", classes="connect_label")
                            yield Select([], id="home_device", allow_blank=True)
                            yield Button("↺", id="home_refresh")

                        with Horizontal(classes="connect_row"):
                            yield Label("Mode", classes="connect_label")
                            yield Select(
                                [("Attach (app name)", "n"), ("Attach (PID)", "p"), ("Spawn", "f")],
                                id="home_mode", value="f", allow_blank=False,
                            )

                        with Horizontal(classes="connect_row"):
                            yield Label("Target", classes="connect_label")
                            yield Select([], id="home_target_select", allow_blank=True)
                            yield Button("↺", id="home_target_refresh")

                        with Horizontal(classes="connect_row"):
                            yield Label("Hook config", classes="connect_label")
                            yield Input(id="home_hooks_path", placeholder="additional hook definitions (.json)", select_on_focus=False)
                            yield Button("Browse", id="home_hooks_browse")
                            yield Button("✕", id="home_hooks_clear")

                        with Horizontal(classes="connect_row"):
                            yield Label("Extra script", classes="connect_label")
                            yield Input(id="home_script_path", placeholder="appended Frida agent (.js)", select_on_focus=False)
                            yield Button("Browse", id="home_script_browse")
                            yield Button("✕", id="home_script_clear")

                        with Horizontal(classes="connect_row", id="home_anr_row"):
                            yield Label("Input ANR bypass (experimental)", id="home_anr_bypass_label")
                            yield Switch(value=False, id="home_system_anr_bypass")

                        yield Rule()
                        with Horizontal(id="home_btn_row"):
                            yield Button("Connect", id="home_btn")
                            yield Button("Disconnect", id="home_disconnect", disabled=True)
                        yield Label("", id="home_error")
            with TabPane(" Intercept ", id="tab_intercept"):
                yield Horizontal(
                    Button(
                        "Intercept on" if self._intercept_mode else "Intercept off",
                        id="intercept_toggle",
                        classes="intercept-on" if self._intercept_mode else "intercept-off",
                    ),
                    Button("Forward", id="btn_forward", variant="default", disabled=True),
                    Button("Drop", id="btn_drop", variant="default", disabled=True),
                    Button("✎", id="btn_edit", disabled=True),
                    Label("", id="intercept_header_spacer"),
                    Button("Filters", id="btn_intercept_filters"),
                    Button("Stack", id="btn_intercept_stack"),
                    id="intercept_header",
                )
                yield RichLog(id="intercept_output", markup=True, highlight=False, auto_scroll=False)
                with VerticalScroll(id="edit_form"):
                    with Horizontal(classes="ef_row"):
                        yield Label("Action", classes="ef_label")
                        yield Input(id="ef_action", placeholder="e.g. android.intent.action.VIEW")
                    with Horizontal(classes="ef_row"):
                        yield Label("Data URI", classes="ef_label")
                        yield Input(id="ef_data", placeholder="e.g. https://example.com")
                    yield Rule()
                    yield Label("Categories", classes="ef_section")
                    yield Vertical(id="ef_categories")
                    yield Button("+ category", id="ef_add_cat")
                    yield Rule()
                    yield Label("Extras", classes="ef_section")
                    yield Vertical(id="ef_extras")
                    yield Button("+ extra", id="ef_add_extra")
                    yield Rule()
                    yield Label("Flags", classes="ef_section")
                    with Horizontal(classes="ef_row"):
                        yield Label("Value", classes="ef_label")
                        yield Input(id="ef_flags", placeholder="e.g. 0x10000000")
                yield RichLog(id="intercept_cmd_output", markup=True, highlight=False)
                yield OptionList(id="intercept_cmd_suggestions")
                yield Vertical(
                    Horizontal(
                        Label("❯", id="intercept_prompt_char"),
                        Input(
                            id="intercept_command_input",
                            disabled=True,
                            placeholder="Intent command, or / for app commands",
                            suggester=CommandSuggester(INTERCEPT_COMPLETIONS),
                            select_on_focus=False,
                        ),
                        id="intercept_input_bar"
                    ),
                    id="intercept_input_wrapper"
                )
            with TabPane(" History ", id="tab_history"):
                with Horizontal(id="history_header"):
                    yield Button("Filters", id="btn_history_filters")
                    yield Button("Stack", id="btn_history_stack")
                    yield Label("", id="filter_bar_spacer")
                    yield Input(id="history_search", placeholder="Search", select_on_focus=False)
                    yield Button("⊟", id="btn_columns")
                yield DataTable(id="history_table", cursor_type="row")
                yield RichLog(id="history_detail", markup=True, highlight=False, auto_scroll=False)
            with TabPane(" Log ", id="tab_log"):
                with Horizontal(id="log_header"):
                    yield Label("Verbose logs", id="log_verbose_label")
                    yield Switch(value=self._log_verbose, id="log_verbose")
                yield RichLog(id="log_output", markup=True, highlight=False)
            with TabPane(" Settings ", id="tab_settings"):
                with VerticalScroll(id="settings_pane"):
                    yield Label("Startup Settings", id="settings_title")
                    yield Rule()
                    with Horizontal(classes="settings_row settings_switch_row"):
                        yield Label("Intercept on startup")
                        yield Switch(value=self._settings["intercept"], id="settings_intercept")
                    with Horizontal(classes="settings_row settings_switch_row"):
                        yield Label("Stack trace on startup")
                        yield Switch(value=self._settings["stack"], id="settings_stack")
                    with Horizontal(classes="settings_row"):
                        yield Label("Stack depth")
                        yield Input(
                            value=str(self._settings["stack_depth"]),
                            id="settings_depth_input",
                            select_on_focus=False,
                        )
                    yield Label("", id="settings_depth_error")
                    yield Rule()
                    yield Button("Save", id="settings_save", variant="primary")
        with Vertical(id="history_bar_container"):
            yield RichLog(id="history_cmd_output", markup=True, highlight=False)
            yield OptionList(id="history_cmd_suggestions")
            yield Vertical(
                Horizontal(
                    Label("❯", id="history_prompt_char"),
                    Input(
                        id="history_command_input",
                        placeholder="Type / for history commands",
                        suggester=CommandSuggester(HISTORY_COMPLETIONS, use_cache=False),
                        select_on_focus=False,
                    ),
                    id="history_input_bar",
                ),
                id="history_input_wrapper",
            )
        with Horizontal(id="app_footer"):
            yield Footer()
            yield Label("", id="filter_count_label")

    def on_mount(self):
        for btn_id in (
            "intercept_toggle",
            "btn_forward",
            "btn_drop",
            "btn_edit",
            "btn_intercept_filters",
            "btn_intercept_stack",
            "btn_history_filters",
            "btn_history_stack",
            "btn_columns",
        ):
            self.query_one(f"#{btn_id}", Button).active_effect_duration = 0
        self._apply_command_bar_visibility()
        self._refresh_history_table()
        self._update_filter_count()
        self.query_one("#session_info", Label).update("Not connected")
        self.write_log(log_info("Ready", "noxen"))
        for msg in self._startup_messages:
            self.write_log(msg)

        if not self._skip_startup_device_scan:
            self._populate_home_devices()
        self.query_one("#main_tabs", TabbedContent).active = "tab_home"

    def _set_path_input(self, widget_id: str, path: str | None) -> None:
        if path:
            try:
                self.query_one(f"#{widget_id}", Input).value = path
            except Exception:
                pass

    def _try_connect(self):
        device_id = self.query_one("#home_device", Select).value
        if not getattr(self, "_home_devices", []) or is_select_empty(device_id):
            self.query_one("#home_error", Label).update("[red]No device available[/red]")
            return

        mode = self.query_one("#home_mode", Select).value
        target_val = self.query_one("#home_target_select", Select).value
        if is_select_empty(target_val):
            self.query_one("#home_error", Label).update("[red]Select a target[/red]")
            return
        target = str(target_val)

        self.query_one("#home_error", Label).update("")

        if self.frida_session:
            self.frida_session.cleanup()
            self.frida_session = None

        self._startup_messages.clear()
        self.set_intercept_state(False)

        hooks_path = self.query_one("#home_hooks_path", Input).value.strip() or None
        script_path = self.query_one("#home_script_path", Input).value.strip() or None
        self._init_session(SessionConfig(
            spawn_package=target if mode == "f" else None,
            attach_name=target if mode == "n" else None,
            attach_pid=int(target) if mode == "p" else None,
            custom_hooks=hooks_path,
            extra_script=script_path,
        ))
        for msg in self._startup_messages:
            self.write_log(msg)
        self._refresh_history_table()

        self.query_one("#main_tabs", TabbedContent).active = "tab_intercept"
        self.on_device_selected(device_id)

    def on_select_changed(self, event: Select.Changed):
        if event.select.id in ("home_device", "home_mode"):
            self._populate_target_apps()

    def on_device_selected(self, device_id):
        if not device_id:
            self.write_cmd("[red]No device selected[/red]")
            self.exit()
            return

        cfg = self._session_config
        target = cfg.target_label()
        self._session_device_id = device_id
        self.query_one("#session_info", Label).update(f"{target}  ·  {device_id}")

        self.db.set_info("target", target)
        self.db.set_info("device_id", device_id)

        self.query_one("#intercept_command_input", Input).disabled = False
        self._focus_intercept_default()
        session = self.frida_session
        session.api_level_cb = lambda sdk_int, session=session: self._on_api_level(sdk_int, session)
        session.connected_cb = lambda session=session: self._on_connected(session)
        session.disconnected_cb = lambda session=session: self._on_disconnected(session)
        if self._system_anr_bypass_enabled:
            self._ensure_system_anr_bypass(device_id)
        session.connect(device_id)

    def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id == "log_verbose":
            self._log_verbose = event.value
            self._refresh_log_output()
            return

        if event.switch.id != "home_system_anr_bypass":
            return
        self._system_anr_bypass_enabled = event.value
        if event.value and self._session_device_id:
            self._ensure_system_anr_bypass(self._session_device_id)
        elif not event.value and self.system_server_session:
            self._cleanup_system_server_session()
            self.write_log(log_warning("Input ANR bypass disabled", "input-anr"))

    def _ensure_system_anr_bypass(self, device_id: str) -> None:
        if self.system_server_session is None:
            self.system_server_session = SystemServerSession(
                SystemServerConfig(),
                log_cb=self.write_log,
            )
        self.system_server_session.connect(device_id)

    def _on_hold_start(self, payload: dict) -> None:
        if self._system_anr_bypass_enabled and self.system_server_session:
            self.system_server_session.hold_start(payload)

    def _on_hold_end(self, payload: dict) -> None:
        if self.system_server_session:
            self.system_server_session.hold_end(payload.get("holdId"), payload.get("pid"))

    def _cleanup_system_server_session(self, async_cleanup: bool = False) -> None:
        session = self.system_server_session
        self.system_server_session = None
        if session is None:
            return
        if async_cleanup:
            threading.Thread(target=session.cleanup, daemon=True).start()
        else:
            session.cleanup()

    def _populate_home_devices(self):
        self._connect_scan_generation += 1
        generation = self._connect_scan_generation
        try:
            self.query_one("#home_error", Label).update("Scanning devices...")
        except Exception:
            pass
        self._populate_home_devices_worker(generation)

    @work(thread=True)
    def _populate_home_devices_worker(self, generation: int):
        try:
            import frida
            candidates = prefer_non_local_devices(frida.enumerate_devices())
            options = [(f"{d.name}  ({d.type})", d.id) for d in candidates]

            def _update():
                if generation != self._connect_scan_generation:
                    return
                try:
                    select = self.query_one("#home_device", Select)
                    select.set_options(options)
                    option_values = {value for _label, value in options}
                    if select.value not in option_values:
                        usb = next((d for d in candidates if getattr(d, "type", None) == "usb"), None)
                        default = usb or (candidates[0] if candidates else None)
                        select.value = default.id if default else SELECT_EMPTY
                    self.query_one("#home_error", Label).update("")
                except Exception:
                    pass
                self._home_devices = candidates

            self.call_from_thread(_update)
        except Exception as e:
            error = str(e)

            def _err():
                if generation != self._connect_scan_generation:
                    return
                try:
                    self.query_one("#home_error", Label).update(f"[red]Devices: {error}[/red]")
                except Exception:
                    pass
                self._home_devices = []

            self.call_from_thread(_err)

    def _populate_target_apps(self):
        device_id = self.query_one("#home_device", Select).value
        mode = self.query_one("#home_mode", Select).value
        if is_select_empty(device_id) or is_select_empty(mode):
            return
        self._populate_target_apps_worker(str(device_id), str(mode))

    @work(thread=True)
    def _populate_target_apps_worker(self, device_id: str, mode: str):
        try:
            import frida
            device = frida.get_device(device_id)
            if mode == "f":
                items = device.enumerate_applications()
                options = sorted(
                    [(a.identifier, a.identifier) for a in items],
                    key=lambda x: x[0].lower(),
                )
            else:
                items = device.enumerate_processes()
                if mode == "p":
                    options = sorted(
                        [(f"{p.name}  (PID {p.pid})", str(p.pid)) for p in items],
                        key=lambda x: x[0].lower(),
                    )
                else:
                    options = sorted(
                        [(p.name, p.name) for p in items],
                        key=lambda x: x[0].lower(),
                    )

            def _update():
                try:
                    self.query_one("#home_target_select", Select).set_options(options)
                except Exception:
                    pass

            self.call_from_thread(_update)
        except Exception as e:
            error = str(e)
            def _err():
                try:
                    self.query_one("#home_error", Label).update(f"[red]Apps: {error}[/red]")
                except Exception:
                    pass
            self.call_from_thread(_err)

    def _on_api_level(self, sdk_int, session=None):
        if session is not None and session is not self.frida_session:
            return
        cfg = self._session_config
        target = cfg.target_label()
        def _do():
            self.query_one("#session_info", Label).update(
                f"{target}  ·  {self._session_device_id}  ·  API {sdk_int}"
            )
        try:
            self.call_from_thread(_do)
        except Exception:
            pass

    def _on_connected(self, session=None):
        if session is not None and session is not self.frida_session:
            return
        def _do():
            try:
                self.query_one("#session_bar").add_class("connected")
                self.query_one("#home_disconnect", Button).disabled = False
            except Exception:
                pass
        try:
            self.call_from_thread(_do)
        except Exception:
            pass

    def _on_disconnected(self, session=None):
        if session is not None and session is not self.frida_session:
            return
        self.frida_session = None
        self._cleanup_system_server_session(async_cleanup=True)
        self.set_intercept_state(False)

        def _do():
            try:
                self.query_one("#session_bar").remove_class("connected")
                self.query_one("#session_info", Label).update("Not connected")
                self.query_one("#home_disconnect", Button).disabled = True
            except Exception:
                pass
        try:
            self.call_from_thread(_do)
        except Exception:
            pass

    def _do_disconnect(self):
        if self.frida_session:
            self.frida_session.cleanup()
            self.frida_session = None
        self._cleanup_system_server_session()
        self.set_intercept_state(False)
        try:
            self.query_one("#session_bar").remove_class("connected")
            self.query_one("#session_info", Label).update("Not connected")
            self.query_one("#home_disconnect", Button).disabled = True
        except Exception:
            pass

    def _write_rich(self, widget_id: str, text: str, notify: bool = False) -> None:
        plain = re.sub(r"\[/?[^\]]*\]", "", text).strip() if notify else ""

        def _do():
            try:
                self.query_one(f"#{widget_id}", RichLog).write(text)
            except Exception:
                pass
            if notify and plain:
                if "[red]" in text:
                    sev = "error"
                elif "[yellow]" in text:
                    sev = "warning"
                else:
                    sev = "information"
                self.notify(plain[:160], severity=sev, timeout=3)

        if threading.current_thread() is threading.main_thread():
            _do()
        else:
            self.call_from_thread(_do)

    def write_log(self, text: str, notify: bool = False) -> None:
        self._log_entries.append(text)
        if self._is_log_visible(text):
            self._write_rich("log_output", text, notify)

    def _is_log_visible(self, text: str) -> bool:
        return self._log_verbose or not is_debug_log(text)

    def _refresh_log_output(self) -> None:
        def _do():
            try:
                output = self.query_one("#log_output", RichLog)
                output.clear()
                for entry in self._log_entries:
                    if self._is_log_visible(entry):
                        output.write(entry)
            except Exception:
                pass

        if threading.current_thread() is threading.main_thread():
            _do()
        else:
            self.call_from_thread(_do)

    def write_cmd(self, text: str, notify: bool = False) -> None:
        self._write_rich("intercept_cmd_output", text, notify)

    # --- History callbacks ---

    def _on_history_intent(self, payload, _history_id):
        entry = payload_to_history_entry(payload)
        db_id = self.db.save_intent(entry)
        entry["id"] = db_id if db_id else len(self._all_intents) + 1
        self._all_intents.append(entry)
        self._pending_append.append(entry)
        if not self._history_refresh_pending:
            self._history_refresh_pending = True
            self.call_from_thread(self._do_history_refresh)
        return entry["id"]

    def _do_history_refresh(self):
        self._history_refresh_pending = False
        pending = self._pending_append[:]
        self._pending_append.clear()
        if not pending:
            return
        try:
            table = self.query_one("#history_table", DataTable)
            has_columns = len(table.columns) > 0
        except Exception:
            self._refresh_history_table()
            return
        if not has_columns:
            self._refresh_history_table()
            return
        if self._sort_column is not None:
            # Sorted: rows need reordering but columns are already correct
            self._refresh_rows_only()
            return
        # Unsorted fast path: batch-append without any rebuild
        saved_cursor = table.cursor_row
        for entry in pending:
            self._append_history_row(entry)
        if saved_cursor >= 0:
            self.set_timer(0, lambda t=table, c=saved_cursor: t.move_cursor(row=c, animate=False))

    def _append_history_row(self, entry):
        """Append a single row to the table without full rebuild."""
        try:
            table = self.query_one("#history_table", DataTable)
        except Exception:
            return
        ctx = entry_to_filter_context(entry)
        if not self._history_filter_manager.is_visible(ctx):
            return
        row_vals = history_row_values(entry, self._history_visible_cols, _HISTORY_COLUMNS)
        table.add_row(*row_vals, key=str(entry["id"]))

    def _update_filter_count(self):
        if self._active_tab == "tab_intercept":
            fm = self.filter_manager
        elif self._active_tab == "tab_history":
            fm = self._history_filter_manager
        else:
            try:
                self.query_one("#filter_count_label", Label).update("")
            except Exception:
                pass
            return
        active = sum(1 for f in fm.export() if f.get("enabled", True))
        total = len(fm.export())
        if total == 0:
            text = ""
        elif active == total:
            text = f"Filters: {total}"
        else:
            text = f"Filters: {active}/{total}"
        try:
            self.query_one("#filter_count_label", Label).update(text)
        except Exception:
            pass

    def _on_intercept_filters_changed(self):
        """Save intercept filters to DB."""
        self.db.save_intercept_filters(self.filter_manager.export())
        self._update_filter_count()

    def _on_columns_changed(self, visible: set):
        """Save visible columns to DB and refresh table."""
        self._history_visible_cols = visible
        self.db.save_history_columns(list(visible))
        self._refresh_history_table()

    def _on_history_filters_changed(self):
        """Save history filters to DB then refresh the table."""
        self.db.save_history_filters(self._history_filter_manager.export())
        self._refresh_history_table()
        self._update_filter_count()

    def _get_filtered_sorted(self):
        """Return filtered+sorted snapshot of all intents."""
        return filter_sort_history_entries(
            self._all_intents,
            self._history_filter_manager,
            self._history_search_text,
            self._sort_column,
            self._sort_reverse,
        )

    def _fill_table_rows(self, table, filtered):
        """Add rows to table from a filtered+sorted entry list."""
        for entry in filtered:
            row_vals = history_row_values(entry, self._history_visible_cols, _HISTORY_COLUMNS)
            table.add_row(*row_vals, key=str(entry["id"]))

    def _restore_cursor(self, table, filtered, saved_sel_id):
        """Restore cursor to previously selected row by id."""
        if not saved_sel_id:
            return
        idx = next((i for i, e in enumerate(filtered) if str(e.get("id")) == saved_sel_id), None)
        if idx is None:
            return
        table.move_cursor(row=idx, animate=False)
        def _restore(t=table, sid=saved_sel_id):
            try:
                for i, rk in enumerate(t.rows):
                    if str(rk.value) == sid:
                        t.move_cursor(row=i, animate=False)
                        break
            except Exception:
                pass
        self.set_timer(0.1, _restore)

    def _refresh_rows_only(self):
        """Rebuild rows without touching columns (sort stable, columns unchanged)."""
        try:
            table = self.query_one("#history_table", DataTable)
        except Exception:
            return
        saved_sel_id = str(self._history_selected_entry["id"]) if self._history_selected_entry else None
        filtered = self._get_filtered_sorted()
        table.clear(columns=False)
        self._fill_table_rows(table, filtered)
        self._restore_cursor(table, filtered, saved_sel_id)

    def _refresh_history_table(self):
        try:
            table = self.query_one("#history_table", DataTable)
        except Exception:
            return
        saved_sel_id = str(self._history_selected_entry["id"]) if self._history_selected_entry else None
        filtered = self._get_filtered_sorted()

        # Rebuild columns with sort indicator (only visible ones)
        visible = self._history_visible_cols
        table.clear(columns=True)
        for key, label in _HISTORY_COLUMNS:
            if key not in visible:
                continue
            indicator = (" ↓" if self._sort_reverse else " ↑") if key == self._sort_column else ""
            table.add_column(label + indicator, key=key)

        self._fill_table_rows(table, filtered)
        self._restore_cursor(table, filtered, saved_sel_id)


    def _on_intercept_display(self, _text, entry_id=None, decision_id=None):
        entry = None
        if entry_id is not None:
            entry = next((e for e in self._all_intents if e["id"] == entry_id), None)
        elif self._all_intents:
            entry = self._all_intents[-1]

        if entry is None:
            self._current_intercept_id = None
            self._current_decision_id = decision_id
            self._current_intercepted_entry = None
            self._staged_mods.clear()
            self._write_rich("intercept_output", _text)
            return

        self._current_intercept_id = entry["id"]
        self._current_decision_id = decision_id
        self._current_intercepted_entry = entry
        self._staged_mods.clear()
        rendered = render_intent_detail(entry, show_stack=self.show_stack, stack_depth=self.stack_depth)

        def _do():
            try:
                intercept_output = self.query_one("#intercept_output", RichLog)
                intercept_output.clear()
                intercept_output.write(rendered)
            except Exception:
                pass

        if threading.current_thread() is threading.main_thread():
            _do()
        else:
            self.call_from_thread(_do)

    # --- DataTable row selection ---

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted):
        if event.data_table.id != "history_table":
            return
        if event.row_key is None or event.row_key.value is None:
            return
        entry_id = int(event.row_key.value)
        entry = next((e for e in self._all_intents if e["id"] == entry_id), None)
        if entry:
            self._history_selected_entry = entry
            try:
                detail = self.query_one("#history_detail", RichLog)
                detail.clear()
                detail.write(render_intent_detail(
                    entry,
                    show_stack=self._history_show_stack,
                    stack_depth=self._history_stack_depth,
                ))
                detail.scroll_home(animate=False)
            except Exception:
                pass

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected):
        if event.data_table.id != "history_table":
            return
        col_key = event.column_key.value
        if self._sort_column == col_key:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_column = col_key
            self._sort_reverse = False
        self._refresh_history_table()

    # --- Tab switching ---

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated):
        if event.pane is None:
            return
        pane_id = event.pane.id
        self._active_tab = pane_id
        self.refresh_bindings()
        self._apply_history_command_bar_visibility()
        if pane_id == "tab_intercept":
            try:
                self.query_one("#main_tabs", TabbedContent).get_tab("tab_intercept").remove_class("intercepted")
            except Exception:
                pass
            self._focus_intercept_default()
        elif pane_id == "tab_history":
            self._focus_history_main_panel()
            if self._history_table_height is None:
                self.call_after_refresh(self._init_panel_heights)
        elif pane_id == "tab_log":
            try:
                self.query_one("#log_output", RichLog).focus()
            except Exception:
                pass
        self._update_filter_count()

    # --- Actions ---


    def set_intercept_state(self, is_intercepted):
        def _do_update():
            try:
                bar = self.query_one("#intercept_input_bar")
                if is_intercepted:
                    bar.add_class("intercepted")
                else:
                    bar.remove_class("intercepted")
                fwd = self.query_one("#btn_forward", Button)
                drp = self.query_one("#btn_drop", Button)
                edit = self.query_one("#btn_edit", Button)
                if is_intercepted:
                    self._set_intercept_action_button_classes(fwd, "forward-ready")
                    self._set_intercept_action_button_classes(drp, "drop-ready")
                    self._set_intercept_action_button_classes(edit, "edit-ready")
                else:
                    self._set_intercept_action_button_classes(fwd)
                    self._set_intercept_action_button_classes(drp)
                    self._set_intercept_action_button_classes(edit)
                fwd.disabled = not is_intercepted
                drp.disabled = not is_intercepted
                edit.disabled = not is_intercepted
                if not is_intercepted and self._edit_mode:
                    self._exit_edit_mode()
            except Exception:
                pass
            try:
                tab = self.query_one("#main_tabs", TabbedContent).get_tab("tab_intercept")
                if is_intercepted and self._active_tab != "tab_intercept":
                    tab.add_class("intercepted")
                else:
                    tab.remove_class("intercepted")
            except Exception:
                pass

        if threading.current_thread() is threading.main_thread():
            _do_update()
        else:
            self.call_from_thread(_do_update)


    def action_clear_history(self):
        self._all_intents.clear()
        self._history_selected_entry = None
        try:
            self.query_one("#history_table", DataTable).clear(columns=False)
            self.query_one("#history_detail", RichLog).clear()
        except Exception:
            pass
        if self.db:
            self.db.clear_intents()
        self.write_log(log_success("History cleared", "history"), notify=True)

    def check_action(self, action: str, parameters) -> bool | None:
        if action == "clear_log":
            return self._active_tab in ("tab_log", "tab_history")
        if action == "toggle_command_bar":
            return self._active_tab in ("tab_history", "tab_intercept")
        if action in ("resize_panel_up", "resize_panel_down"):
            if self._active_tab == "tab_intercept":
                return True if self._intercept_command_bar_visible else None
            return True if self._active_tab == "tab_history" else None
        return True

    def on_resize(self, _event: events.Resize) -> None:
        if self._active_tab == "tab_history":
            self.call_after_refresh(self._clamp_history_table_to_available_space)
        if self._active_tab == "tab_intercept" and self._intercept_command_bar_visible:
            self.call_after_refresh(self._clamp_intercept_command_output_to_available_space)

    def _widget_height(self, selector: str) -> int | None:
        try:
            height = self.query_one(selector).size.height
        except Exception:
            LOGGER.debug("Unable to read height for %s", selector, exc_info=True)
            return None
        return height if height > 0 else None

    def _set_widget_height(self, selector: str, height: int) -> bool:
        try:
            self.query_one(selector).styles.height = height
        except Exception:
            LOGGER.warning("Unable to set height for %s to %s", selector, height, exc_info=True)
            return False
        return True

    def _init_panel_heights(self) -> bool:
        height = self._widget_height("#history_table")
        if height is None:
            return False
        return self._set_history_table_height(height)

    def _max_history_table_height(self) -> int | None:
        table_height = self._widget_height("#history_table")
        detail_height = self._widget_height("#history_detail")
        if table_height is None or detail_height is None:
            return None
        return max_primary_panel_height(table_height, detail_height, MIN_HISTORY_DETAIL_HEIGHT)

    def _set_history_table_height(self, height: int) -> bool:
        max_height = self._max_history_table_height()
        height = clamp_height(height, MIN_PANEL_HEIGHT, max_height)
        if not self._set_widget_height("#history_table", height):
            return False
        self._history_table_height = height
        return True

    def _adjust_history_split(self, delta: int):
        if self._history_table_height is None and not self._init_panel_heights():
            return
        self._set_history_table_height(self._history_table_height + delta)

    def _clamp_history_table_to_available_space(self) -> None:
        if self._history_table_height is None:
            self._init_panel_heights()
            return
        self._set_history_table_height(self._history_table_height)

    def _max_intercept_command_output_height(self) -> int:
        cmd_height = self._widget_height("#intercept_cmd_output")
        body_height = self._widget_height("#edit_form" if self._edit_mode else "#intercept_output")
        dynamic_max = None
        if cmd_height is not None and body_height is not None:
            dynamic_max = max_primary_panel_height(cmd_height, body_height, MIN_PANEL_HEIGHT)
        hard_max = MAX_COMMAND_OUTPUT_HEIGHT
        if dynamic_max is not None:
            hard_max = min(hard_max, clamp_height(dynamic_max, MIN_PANEL_HEIGHT))
        return hard_max

    def _adjust_intercept_cmd(self, delta: int):
        new_height = clamp_height(
            self._intercept_cmd_height + delta,
            MIN_PANEL_HEIGHT,
            self._max_intercept_command_output_height(),
        )
        if self._set_widget_height("#intercept_cmd_output", new_height):
            self._intercept_cmd_height = new_height

    def _clamp_intercept_command_output_to_available_space(self) -> None:
        new_height = clamp_height(
            self._intercept_cmd_height,
            MIN_PANEL_HEIGHT,
            self._max_intercept_command_output_height(),
        )
        if new_height != self._intercept_cmd_height and self._set_widget_height("#intercept_cmd_output", new_height):
            self._intercept_cmd_height = new_height

    def _adjust_history_cmd_output_height(self, delta: int):
        new_height = clamp_height(
            self._history_cmd_height + delta,
            MIN_PANEL_HEIGHT,
            MAX_COMMAND_OUTPUT_HEIGHT,
        )
        if self._set_widget_height("#history_cmd_output", new_height):
            self._history_cmd_height = new_height

    def _focused_in_cmd_area(self) -> bool:
        fid = getattr(self.focused, "id", None)
        if fid in ("intercept_command_input", "intercept_cmd_output"):
            return self._intercept_command_bar_visible
        if fid in ("history_command_input", "history_cmd_output"):
            return self._history_command_bar_visible
        return False

    def action_resize_panel_up(self):
        if self._active_tab == "tab_intercept":
            if not self._intercept_command_bar_visible:
                return
            self._adjust_intercept_cmd(1)
        elif self._active_tab == "tab_history":
            if self._focused_in_cmd_area():
                self._adjust_history_cmd_output_height(1)
            else:
                self._adjust_history_split(-1)

    def action_resize_panel_down(self):
        if self._active_tab == "tab_intercept":
            if not self._intercept_command_bar_visible:
                return
            self._adjust_intercept_cmd(-1)
        elif self._active_tab == "tab_history":
            if self._focused_in_cmd_area():
                self._adjust_history_cmd_output_height(-1)
            else:
                self._adjust_history_split(1)

    def action_toggle_command_bar(self):
        if self._active_tab == "tab_intercept":
            self._toggle_intercept_command_bar()
        elif self._active_tab == "tab_history":
            self._toggle_history_command_bar()

    def on_key(self, event):
        if event.key == "ctrl+enter" and self._edit_mode:
            self._forward_from_edit_mode()
            event.stop()
            return

        focused = self.focused
        if not focused:
            return
        fid = getattr(focused, "id", None)

        if fid == "history_search":
            if event.key == "escape":
                event.stop()
                try:
                    self.query_one("#history_search", Input).value = ""
                    self.query_one("#history_table", DataTable).focus()
                except Exception:
                    pass
            return
        if fid not in ("intercept_command_input", "history_command_input"):
            return
        ol_id = "intercept_cmd_suggestions" if fid == "intercept_command_input" else "history_cmd_suggestions"
        try:
            ol = self.query_one(f"#{ol_id}", OptionList)
        except Exception:
            return
        if not ol.display:
            return

        if event.key == "down":
            event.prevent_default()
            event.stop()
            count = ol.option_count
            if count > 0:
                ol.highlighted = min((ol.highlighted or 0) + 1, count - 1)
        elif event.key == "up":
            event.prevent_default()
            event.stop()
            ol.highlighted = max((ol.highlighted or 0) - 1, 0)
        elif event.key == "tab":
            event.prevent_default()
            event.stop()
            self._apply_suggestion_from(ol_id, fid)
        elif event.key == "escape":
            event.stop()
            ol.display = False

    def _get_suggestion_fill(self, ol_id: str) -> str | None:
        try:
            ol = self.query_one(f"#{ol_id}", OptionList)
        except Exception:
            return None
        if ol.option_count == 0:
            return None
        idx = ol.highlighted if ol.highlighted is not None else 0
        return completion_fill_from_prompt(ol.get_option_at_index(idx).prompt)

    def _apply_suggestion_from(self, ol_id: str, inp_id: str):
        try:
            ol = self.query_one(f"#{ol_id}", OptionList)
            inp = self.query_one(f"#{inp_id}", Input)
        except Exception:
            return
        fill = self._get_suggestion_fill(ol_id)
        if fill is None:
            return
        inp.value = fill
        inp.cursor_position = len(inp.value)
        ol.display = False
        inp.focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected):
        ol_id = getattr(event.option_list, "id", None)
        if ol_id not in ("intercept_cmd_suggestions", "history_cmd_suggestions"):
            return
        event.stop()
        fill = completion_fill_from_prompt(event.option.prompt)
        inp_id = "intercept_command_input" if ol_id == "intercept_cmd_suggestions" else "history_command_input"
        try:
            inp = self.query_one(f"#{inp_id}", Input)
            ol = self.query_one(f"#{ol_id}", OptionList)
            inp.value = fill
            inp.cursor_position = len(fill)
            ol.display = False
            inp.focus()
        except Exception:
            pass

    def on_input_changed(self, event: Input.Changed):
        inp_id = event.input.id
        text = event.value.strip()
        if inp_id == "history_search":
            self._history_search_text = text
            self._refresh_rows_only()
            return
        if inp_id == "intercept_command_input":
            ol_id = "intercept_cmd_suggestions"
            matches = matching_completions(INTERCEPT_COMPLETIONS, text)
        elif inp_id == "history_command_input":
            ol_id = "history_cmd_suggestions"
            matches = matching_completions(HISTORY_COMPLETIONS, text)
        else:
            return
        try:
            ol = self.query_one(f"#{ol_id}", OptionList)
        except Exception:
            return
        if not text:
            ol.display = False
            return
        ol.clear_options()
        if not matches:
            ol.display = False
            return
        for template, desc in matches:
            ol.add_option(format_completion_option(template, desc))
        ol.highlighted = 0
        ol.display = True

    def on_input_submitted(self, event: Input.Submitted):
        inp_id = getattr(event.input, "id", None)

        if inp_id == "settings_depth_input":
            try:
                val = int(event.value.strip())
                if val < 1:
                    raise ValueError
                self._settings["stack_depth"] = val
                save_settings(self._settings)
                self.query_one("#settings_depth_error", Label).update("")
            except ValueError:
                self.query_one("#settings_depth_error", Label).update("Enter a positive integer")
            return

        if inp_id == "history_command_input":
            ol_id = "history_cmd_suggestions"
            cmd_to_run = event.value.strip()
            try:
                ol = self.query_one(f"#{ol_id}", OptionList)
                if ol.display and ol.option_count > 0:
                    suggestion = self._get_suggestion_fill(ol_id)
                    submitted = resolve_submitted_command(event.value, suggestion)
                    if submitted.should_complete:
                        self._apply_suggestion_from(ol_id, inp_id)
                        return
                    cmd_to_run = submitted.command
                ol.display = False
            except Exception:
                pass
            event.input.value = ""
            if not cmd_to_run:
                return
            self.process_slash_command_worker(cmd_to_run)
            return

        ol_id = "intercept_cmd_suggestions"
        cmd_to_run = event.value.strip()
        try:
            ol = self.query_one(f"#{ol_id}", OptionList)
            if ol.display and ol.option_count > 0:
                suggestion = self._get_suggestion_fill(ol_id)
                submitted = resolve_submitted_command(event.value, suggestion)
                if submitted.should_complete:
                    self._apply_suggestion_from(ol_id, inp_id)
                    return
                cmd_to_run = submitted.command
            ol.display = False
        except Exception:
            pass
        event.input.value = ""
        if not cmd_to_run:
            return
        self.write_cmd(f"[dim]> {cmd_to_run}[/dim]")
        self.process_command_worker(cmd_to_run)

    def _write_history_command(self, text: str, log: bool = True) -> None:
        if log:
            self.write_log(text)
        self._write_rich("history_cmd_output", text)

    def _handle_slash_command(self, cmd_base: str, parts: list, write_fn=None):
        if write_fn is None:
            write_fn = self.write_cmd

        if cmd_base == "/export":
            parsed = parse_export_command(parts)
            if parsed is None:
                write_fn("[red]Usage: /export entries | /export filtered entries[/red]")
                return
            entries = self._get_filtered_sorted() if parsed.filtered else list(self._all_intents)
            label = history_entries_label(len(entries), filtered=parsed.filtered)
            if not entries:
                write_fn("[dim]No entries to export.[/dim]")
                return
            try:
                result = write_history_export(entries)
                write_fn(f"[#26a368]Exported {result.item_count} {label} to {result.filename}[/#26a368]")
            except Exception as e:
                write_fn(f"[red]Export failed: {e}[/red]")

        elif cmd_base == "/save":
            parsed = parse_save_command(parts)
            if parsed is None:
                write_fn("[red]Usage: /save history filters | /save intercept filters[/red]")
                return
            if parsed.target == "history":
                fm = self._history_filter_manager
            else:
                fm = self.filter_manager
            ignore_list, focus_list = fm.get_active()
            if not ignore_list and not focus_list:
                write_fn("[dim]No active filters to save.[/dim]")
                return
            try:
                result = write_filter_export(ignore_list, focus_list, parsed.file_label)
                write_fn(f"[#26a368]Saved {result.item_count} filter(s) to {result.filename}[/#26a368]")
            except Exception as e:
                write_fn(f"[red]Save failed: {e}[/red]")

        elif cmd_base == "/help":
            menu = HELP_MENU_HISTORY if self._active_tab == "tab_history" else HELP_MENU
            self.call_from_thread(lambda: self.push_screen(HelpModal(menu)))

        elif cmd_base == "/quit":
            self.call_from_thread(self.exit)

        elif cmd_base == "/theme" and parse_theme_command(parts):
            self.call_from_thread(self.action_toggle_theme)

        elif cmd_base == "/clear":
            parsed = parse_clear_command(parts)
            if parsed and parsed.target == "history":
                self.call_from_thread(self.action_clear_history)
            else:
                write_fn("[red]Usage: /clear history[/red]")

        elif cmd_base == "/stack":
            self._handle_stack_command(parts, write_fn)

        elif cmd_base == "/filter":
            self._handle_filter_command(parts, write_fn)

        elif cmd_base == "/intercept":
            self._handle_intercept_command(parts, write_fn)

        else:
            write_fn(f"[red]Unknown command: {' '.join(parts)} (Try '/help')[/red]")

    @work(thread=True)
    def process_slash_command_worker(self, cmd):
        parsed = parse_command(cmd)
        if parsed is None:
            return
        if parsed.base.startswith("/"):
            self._handle_slash_command(parsed.base, parsed.parts, write_fn=self._write_history_command)
        else:
            self._write_history_command("[red]History commands must start with '/' (Try '/help')[/red]", log=False)

    def _handle_stack_command(self, parts, write_fn):
        is_history = self._active_tab == "tab_history"
        current_show = self._history_show_stack if is_history else self.show_stack
        current_depth = self._history_stack_depth if is_history else self.stack_depth

        parsed = parse_stack_command(parts)
        if parsed is None:
            write_fn("[red]Usage: /stack on | /stack off | /stack <number>[/red]")
            return

        if parsed.action == "status":
            state = "ON" if current_show else "OFF"
            color = "green" if current_show else "yellow"
            write_fn(f"[{color}]Stack Trace: {state} (Depth: {current_depth})[/{color}]")
            return

        if parsed.action == "on":
            current_show = True
            write_fn(f"[#26a368]Stack Trace: ON (Depth: {current_depth})[/#26a368]")
        elif parsed.action == "off":
            current_show = False
            write_fn("[yellow]Stack Trace: OFF[/yellow]")
        elif parsed.action == "depth":
            current_depth = parsed.depth
            write_fn(f"[#26a368]Stack Depth set to {current_depth}[/#26a368]")

        if is_history:
            self._history_show_stack = current_show
            self._history_stack_depth = current_depth
            self.call_from_thread(self._refresh_history_detail)
        else:
            self.show_stack = current_show
            self.stack_depth = current_depth
            self.call_from_thread(self._refresh_intercept_display)

    def _active_filter_manager(self):
        if self._active_tab == "tab_history":
            return self._history_filter_manager
        return self.filter_manager

    def _persist_active_filters(self):
        if self._active_tab == "tab_history":
            self.call_from_thread(self._on_history_filters_changed)
        else:
            self._on_intercept_filters_changed()

    def _handle_filter_command(self, parts, write_fn):
        fm = self._active_filter_manager()
        parsed = parse_filter_command(parts)
        if parsed is None:
            if len(parts) >= 2 and parts[1].lower() == "add":
                write_fn("[red]Usage: /filter add ignore key=value | /filter add focus key=value[/red]")
                return
            if len(parts) >= 2 and parts[1].lower() == "remove":
                write_fn("[red]Usage: /filter remove <id>[/red]")
                return
            write_fn("[red]Usage: /filter list | /filter add ignore key=value | /filter add focus key=value | /filter remove <id>[/red]")
            return

        if parsed.action == "list":
            write_fn(fm.format())
            return

        if parsed.action == "add":
            msg = fm.add(parsed.filter_type, parsed.rule_parts)
            write_fn(msg)
            if not msg.startswith("[red]") and not msg.startswith("[yellow]Already exists"):
                self._persist_active_filters()
            return

        if parsed.action == "remove":
            msg = fm.remove(parsed.filter_id)
            write_fn(msg)
            if not msg.startswith("[red]"):
                self._persist_active_filters()
            return

    def _handle_intercept_command(self, parts, write_fn):
        parsed = parse_intercept_command(parts)
        if parsed is None:
            write_fn("[red]Usage: /intercept on | /intercept off | /intercept status[/red]")
            return

        if parsed.action == "status":
            state = "ON" if self._intercept_mode else "OFF"
            color = "green" if self._intercept_mode else "yellow"
            write_fn(f"[{color}]Intercept {state}[/{color}]")
            return

        if not self.frida_session or not self.frida_session.is_ready():
            write_fn("[red]Session not ready[/red]")
            return

        if parsed.action == "on":
            self.frida_session.intercept_on()
            self.update_intercept_button(True)
            write_fn("[#26a368]Intercept ON[/#26a368]")
        else:
            intent_id = self._current_intercept_id
            resolved = self._current_intercepted_entry
            mods = list(self._staged_mods)
            self.frida_session.intercept_off()
            self.set_intercept_state(False)
            self.update_intercept_button(False)
            self._finalize_forward(intent_id, resolved, mods)
            write_fn("[yellow]Intercept OFF[/yellow]")

    def _refresh_history_detail(self):
        if self._history_selected_entry is None:
            return
        try:
            detail = self.query_one("#history_detail", RichLog)
            detail.clear()
            detail.write(render_intent_detail(
                self._history_selected_entry,
                show_stack=self._history_show_stack,
                stack_depth=self._history_stack_depth,
            ))
            detail.scroll_home(animate=False)
        except Exception:
            pass

    def _refresh_intercept_display(self):
        if self._current_intercepted_entry is None:
            return
        try:
            intercept_output = self.query_one("#intercept_output", RichLog)
            intercept_output.clear()
            intercept_output.write(render_intent_detail(
                self._current_intercepted_entry,
                show_stack=self.show_stack,
                stack_depth=self.stack_depth,
            ))
        except Exception:
            pass

    @work(thread=True)
    def process_command_worker(self, cmd):
        parsed = parse_command(cmd)
        if parsed is None:
            return
        parts = parsed.parts
        cmd_base = parsed.base

        try:
            if cmd_base.startswith("/"):
                self._handle_slash_command(cmd_base, parts)
                return

            if parse_intent_command(cmd) is None:
                self.write_cmd(f"[red]Unknown command '{cmd}' — app commands must start with '/' (Try '/help')[/red]")
                return

            if not self.frida_session or not self.frida_session.is_ready():
                self.write_cmd("[red]Session not ready[/red]")
                return

            if cmd_base in ["forward", "f"]:
                if self._edit_mode:
                    self.call_from_thread(self._forward_from_edit_mode)
                    return
                intent_id = self._current_intercept_id
                resolved = self._current_intercepted_entry
                mods = list(self._staged_mods)
                if not self.frida_session.forward(self._current_decision_id):
                    self.write_cmd("[red]No matching intent blocked to forward[/red]")
                    return
                self.set_intercept_state(False)
                self._finalize_forward(intent_id, resolved, mods)
            elif cmd_base in ["drop", "d"]:
                intent_id = self._current_intercept_id
                resolved = self._current_intercepted_entry
                if not self.frida_session.drop(self._current_decision_id):
                    self.write_cmd("[red]No matching intent blocked to drop[/red]")
                    return
                self.set_intercept_state(False)
                self._update_outcome(intent_id, "dropped")
                self._staged_mods.clear()
                self.call_from_thread(lambda e=resolved: self._clear_intercept_output(e))

            else:
                mod, error = parse_intent_mod_command(parts)
                if error:
                    self.write_cmd(error)
                elif mod:
                    self._stage_current_mod(*mod)
                else:
                    self.write_cmd(f"[red]Unknown command '{cmd}' — try /help[/red]")

        except Exception as e:
            self.write_cmd(f"[bold red]Error: {e}[/bold red]")

    def _update_outcome(self, intent_id: int | None, outcome: str) -> None:
        if intent_id is None:
            return
        for e in self._all_intents:
            if e["id"] == intent_id:
                e["outcome"] = outcome
                break
        self.db.update_outcome(intent_id, outcome)

        def _apply():
            try:
                table = self.query_one("#history_table", DataTable)
                if "outcome" in self._history_visible_cols:
                    table.update_cell(str(intent_id), "outcome", HISTORY_OUTCOME_CELL.get(outcome, ""))
            except Exception:
                pass
            if self._history_selected_entry and self._history_selected_entry.get("id") == intent_id:
                self._refresh_history_detail()

        self.call_from_thread(_apply)

    def _clear_intercept_output(self, resolved_entry=None):
        # If a new intent arrived before this clear was scheduled,
        # _current_intercepted_entry will already point to the new entry.
        # In that case don't clear — the new content must stay visible.
        if resolved_entry is not None and self._current_intercepted_entry is not resolved_entry:
            return
        self._current_intercepted_entry = None
        self._current_intercept_id = None
        self._current_decision_id = None
        self._staged_mods.clear()
        try:
            self.query_one("#intercept_output", RichLog).clear()
        except Exception:
            pass

    def on_unmount(self):
        if self.frida_session:
            self.frida_session.disconnected_cb = None
            self.frida_session.cleanup()
        self._cleanup_system_server_session()
        if self.db:
            self.db.close()
