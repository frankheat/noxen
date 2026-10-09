import copy
import logging
import os
import re
import sys
import threading
import time
from datetime import datetime
from importlib.metadata import version as pkg_version, PackageNotFoundError
from pathlib import Path

from textual import events
from textual import work
from textual.worker import get_current_worker
from textual.app import App, ComposeResult
from textual.containers import Vertical, Horizontal, VerticalScroll
from textual.widgets import (
    Button, ContentSwitcher, DataTable, Footer, Input, Label,
    OptionList, RichLog, Rule, Select, Static, Switch, TabbedContent, TabPane,
)
from textual.binding import Binding

from rich.text import Text

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
    parse_search_command,
    parse_stack_command,
    parse_theme_command,
    resolve_submitted_command,
)
from noxen.app_info import (
    COMPONENT_COLUMNS,
    PERMISSION_COLUMNS,
    component_row,
    filter_components,
    filter_permissions,
    permission_row,
    render_component_detail,
    render_overview,
    sort_components,
    sort_permissions,
)
from noxen.agent_loader import HookConfigError, load_hook_config
from noxen.db import ProjectDB
from noxen.exporting import (
    history_entries_label,
    write_filter_export,
    write_history_export,
)
from noxen.filters import FilterManager
from noxen.frida_devices import enumerate_preferred_devices
from noxen.frida_session import FridaSession, SessionConfig
from noxen.history_columns import normalize_history_column_widths
from noxen.intent_mods import (
    EXTRA_TYPE_OPTIONS,
    EXTRA_VALUE_PLACEHOLDERS,
    JAVA_TYPE_TO_SIMPLE,
    apply_mods_to_entry,
    apply_mods_to_intent,
    diff_intents,
    java_type_display,
    parse_flag_value,
    parse_intent_mod_command,
    validate_extra_value,
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
    entry_to_filter_context,
    filter_sort_history_entries,
    history_outcome_cell,
    history_row_values,
    history_search_text,
    payload_to_history_entry,
    render_intent_detail,
)
from noxen.settings import load_settings, save_settings
from noxen.system_server_session import SystemServerConfig, SystemServerSession
from noxen.textual_compat import SELECT_EMPTY, is_select_empty
from noxen.ui_theme import register_noxen_themes, semantic_colors, themed_markup

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


class _EditValidationError(ValueError):
    def __init__(self, message: str, selector: str, title: str = "Invalid extra"):
        super().__init__(message)
        self.selector = selector
        self.title = title


def markup_renderable(markup: str, dark: bool = True) -> Text:
    """Render a builder's markup string without Rich emoji-shortcode substitution.

    Rich treats ``:cd:`` (and similar) as emoji shortcodes, so app/intent data such
    as a signing SHA-256 byte ``0xCD`` would otherwise be shown as 💿 and corrupt the
    captured value. Style tags and the builders' bracket escaping are preserved; only
    the emoji pass is disabled. Use this for every RichLog write of rendered data.
    """
    return Text.from_markup(themed_markup(markup, dark), emoji=False)


def app_markup_renderable(app, markup: str):
    """Render themed markup, while keeping lightweight test doubles compatible."""
    current_theme = getattr(app, "current_theme", None)
    if current_theme is None:
        return markup
    return markup_renderable(markup, dark=current_theme.dark)


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

    def _lerp_color(self, t: float) -> str:
        colors = semantic_colors(self.app.current_theme.dark)
        start = colors.brand_start
        end = colors.brand_end
        r = int(int(start[1:3], 16) + (int(end[1:3], 16) - int(start[1:3], 16)) * t)
        g = int(int(start[3:5], 16) + (int(end[3:5], 16) - int(start[3:5], 16)) * t)
        b = int(int(start[5:7], 16) + (int(end[5:7], 16) - int(start[5:7], 16)) * t)
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
        colors = semantic_colors(self.app.current_theme.dark)
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
            f"[dim]noxen[/dim]    [{colors.success}]{noxen_ver}[/{colors.success}]\n"
            f"[dim]frida[/dim]    [{colors.success}]{frida_ver}[/{colors.success}]\n"
            f"[dim]python[/dim]   [{colors.success}]{py_ver}[/{colors.success}]\n"
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
        Binding("ctrl+r", "info_refresh", "Refresh", show=True, priority=True),
        Binding("ctrl+t", "info_toggle_rail", "Panel", show=True, priority=True),
        Binding("ctrl+f", "forward_current", "Forward", show=True),
        Binding("ctrl+f", "apply_edit", "Apply & Forward", show=True),
        Binding("ctrl+d", "drop_current", "Drop", show=True, priority=True),
        Binding("escape", "cancel_edit", "Cancel edit", show=True),
    ]

    def __init__(self, cli_args):
        super().__init__()
        register_noxen_themes(self)
        self.theme = "noxen-dark"
        self._skip_startup_device_scan = bool(getattr(cli_args, "skip_device_scan", False))
        self._session_config: SessionConfig | None = None
        self._settings = load_settings()
        self.show_stack = self._settings["stack"]
        self.stack_depth = self._settings["stack_depth"]
        self._all_intents = []
        self._app_info: dict | None = None
        # Info app table sort (column key, reverse); session-only. Components start by type.
        self._info_sort: dict[str, tuple[str | None, bool]] = {
            "info_comp_table": ("type", False),
            "info_perm_table": (None, False),
        }
        self._info_selected_component: str | None = None
        self._history_refresh_pending = False
        self._pending_append: list = []
        self._sort_column: str | None = "id"
        self._sort_reverse: bool = True
        self._history_visible_cols: set[str] = {key for key, _ in _HISTORY_COLUMNS}
        self._history_column_widths: dict[str, int] = {}
        self._history_show_stack = False
        self._history_stack_depth: int = self._settings["stack_depth"]
        self._history_selected_entry: dict | None = None
        self._intercept_mode = self._settings["intercept"]
        self._current_intercept_id: int | None = None
        self._current_decision_id: str | None = None
        self._current_intercepted_entry: dict | None = None
        self._intent_blocked = False
        self._edit_mode = False
        self._edit_forward_pending = False
        self._edit_extra_counter = 0
        self._edit_extra_rows: dict = {}
        self._edit_display_info: dict = {}
        self._edit_cat_counter = 0
        self._edit_cat_rows: dict = {}
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
        self._connection_generation = 0
        self._connection_state = "disconnected"
        self._session_device_id = ""
        self._session_api_level: int | None = None
        self._system_anr_bypass_enabled = False
        self._log_verbose = False
        self._log_entries: list[str] = []
        self.system_server_session: SystemServerSession | None = None
        self.frida_session = None
        self.db, self._all_intents = self._init_project(cli_args)
        self._history_search_index = {
            id(entry): history_search_text(entry) for entry in self._all_intents
        }
        saved_cols = self.db.load_history_columns()
        if saved_cols is not None:
            self._history_visible_cols = set(saved_cols)
        self._history_column_widths = self.db.load_history_column_widths()
        self.filter_manager = FilterManager.from_saved(self.db.load_intercept_filters())
        self._history_filter_manager = FilterManager.from_saved(self.db.load_history_filters())

    def _init_project(self, cli_args) -> tuple:
        """Resolve DB path, open or create the project, return (ProjectDB, intents).

        Propagates FileNotFoundError (--project path missing) and FileExistsError
        (--new-project path already taken) so the caller can refuse to launch the
        TUI against a stub DB whose writes would be silently dropped.
        """
        project = getattr(cli_args, "project", None)
        new_project = getattr(cli_args, "new_project", None)

        if project:
            path = project if project.endswith(".noxen") else project + ".noxen"
            db = ProjectDB(path)
            intents = db.open_existing()
            for warning in db.load_warnings:
                self._startup_messages.append(log_warning(warning, "project"))
            self._startup_messages.append(
                log_success(f"Opened project '{db.name or path}' ({len(intents)} intent(s))", "project")
            )
            return db, intents

        if new_project:
            path = new_project if new_project.endswith(".noxen") else new_project + ".noxen"
            db = ProjectDB(path)
            db.create(new_project)
            self._startup_messages.append(log_success(f"Created project '{new_project}' at {path}", "project"))
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
        if self.theme == "noxen-dark":
            self.theme = "noxen-light"
        else:
            self.theme = "noxen-dark"
        self.call_after_refresh(self._refresh_theme_content)

    def _render_markup(self, markup: str) -> Text:
        return app_markup_renderable(self, markup)

    def _refresh_theme_content(self) -> None:
        """Rebuild color-bearing content after switching between paired palettes."""
        try:
            self.query_one("#home_logo", HomeLogo)._render_brand()
            self.query_one("#home_info", HomeInfo).refresh_info()
        except Exception:
            pass
        self._refresh_log_output()
        self._refresh_history_table()
        if self._app_info:
            self._apply_app_info(self._app_info)
        if self._history_selected_entry:
            try:
                detail = self.query_one("#history_detail", RichLog)
                detail.clear()
                detail.write(self._render_markup(render_intent_detail(
                    self._history_selected_entry,
                    show_stack=self._history_show_stack,
                    stack_depth=self._history_stack_depth,
                )))
            except Exception:
                pass
        if self._current_intercepted_entry:
            self._on_intercept_display(
                "",
                self._current_intercepted_entry.get("id"),
                self._current_decision_id,
            )


    def _enter_edit_mode(self):
        if not self._current_intercepted_entry or self._edit_mode:
            return
        original = self._current_intercepted_entry.get("intent", {}) or {}
        draft = apply_mods_to_intent(original, self._staged_mods)
        self._staged_mods.clear()
        self._populate_edit_form(draft)

        self.query_one("#intercept_output").display = False
        ef = self.query_one("#edit_form")
        ef.display = True
        ef.disabled = False
        ef.scroll_home(animate=False)
        self._edit_mode = True
        self._edit_forward_pending = False
        forward_button = self.query_one("#btn_forward", Button)
        forward_button.label = "Apply & Forward"
        forward_button.add_class("apply-forward")
        self.query_one("#btn_cancel_edit", Button).display = True
        edit_button = self.query_one("#btn_edit", Button)
        edit_button.display = False
        self.refresh_bindings()

    def _populate_edit_form(self, info: dict) -> None:
        self._edit_display_info = info

        self.query_one("#ef_action", Input).value = info.get("action", "") or ""
        self.query_one("#ef_data", Input).value = info.get("data", "") or ""

        self.query_one("#ef_categories").remove_children()
        self._edit_cat_rows = {}
        for cat in (info.get("categories", []) or []):
            self._add_edit_category_row(cat)

        self.query_one("#ef_extras").remove_children()
        self._edit_extra_rows = {}
        original_extras = (
            (self._current_intercepted_entry or {}).get("intent", {}).get("extras", {}) or {}
        )
        for key, extra in (info.get("extras", {}) or {}).items():
            java_type = extra.get("type") or ""
            simple_type = None if extra.get("editable") is False else (
                extra.get("noxenType") or JAVA_TYPE_TO_SIMPLE.get(java_type)
            )
            original_extra = original_extras.get(key)
            original_type = None if original_extra is None else (
                original_extra.get("noxenType")
                or JAVA_TYPE_TO_SIMPLE.get(original_extra.get("type") or "")
            )
            is_new = original_extra is None or (
                simple_type is not None and simple_type != original_type
            )
            self._add_edit_extra_row(
                key,
                simple_type,
                str(extra.get("value", "") or ""),
                is_new=is_new,
                java_type=java_type,
                removable=not extra.get("keyTruncated", False),
            )

        flags_val = info.get("flags") or 0
        try:
            self.query_one("#ef_flags", Input).value = hex(int(flags_val)) if flags_val else ""
        except Exception:
            self.query_one("#ef_flags", Input).value = ""

    def _exit_edit_mode(self):
        if not self._edit_mode:
            return
        self.query_one("#intercept_output").display = True
        edit_form = self.query_one("#edit_form")
        edit_form.display = False
        edit_form.disabled = False
        self._edit_mode = False
        self._edit_forward_pending = False
        self._staged_mods.clear()
        self._edit_display_info = {}
        forward_button = self.query_one("#btn_forward", Button)
        forward_button.label = "Forward"
        forward_button.remove_class("apply-forward")
        self.query_one("#btn_cancel_edit", Button).display = False
        self.query_one("#btn_cancel_edit", Button).disabled = False
        self.query_one("#btn_edit", Button).display = True
        self.refresh_bindings()
        try:
            still_intercepted = "intercepted" in self.query_one("#intercept_input_bar").classes
            self.query_one("#btn_edit").disabled = not still_intercepted
            if still_intercepted:
                self.query_one("#btn_forward", Button).disabled = False
                self.query_one("#btn_drop", Button).disabled = False
        except Exception:
            pass

    def _set_edit_forward_pending(self, pending: bool) -> None:
        self._edit_forward_pending = pending
        if not self._edit_mode:
            return
        forward = self.query_one("#btn_forward", Button)
        forward.label = "Applying…" if pending else "Apply & Forward"
        forward.disabled = pending
        self.query_one("#btn_drop", Button).disabled = pending
        self.query_one("#btn_cancel_edit", Button).disabled = pending
        self.query_one("#edit_form").disabled = pending
        self.refresh_bindings()

    def _restore_editor_after_forward_failure(self, message: str) -> None:
        if not self._edit_mode:
            return
        self._set_edit_forward_pending(False)
        self.notify(message, title="Apply & Forward failed", severity="error")

    def _show_edit_validation_error(self, error: _EditValidationError) -> None:
        self.notify(str(error), title=error.title, severity="error")
        try:
            self.query_one(error.selector).focus()
        except Exception:
            pass

    def _mod_safety_error(self, mod: tuple) -> str | None:
        mod_type, key, _value, _extra_type = mod
        if mod_type not in {"extra_add", "extra_rem"}:
            return None
        extras = (
            (self._current_intercepted_entry or {}).get("intent", {}).get("extras", {}) or {}
        )
        if (extras.get(key) or {}).get("keyTruncated"):
            return f"Extra '{key}' has a truncated key and cannot be modified safely"
        return None

    def _apply_command_mod_to_editor(self, mod: tuple) -> str | None:
        if not self._edit_mode:
            return "The visual Intent editor is no longer active"
        if self._edit_forward_pending:
            return "Apply & Forward is already in progress"
        if error := self._mod_safety_error(mod):
            return error
        try:
            draft = self._collect_edit_draft()
        except _EditValidationError as error:
            self._show_edit_validation_error(error)
            return f"Fix the invalid editor field first: {error}"
        self._populate_edit_form(apply_mods_to_intent(draft, [mod]))
        return None

    def _add_edit_category_row(self, value: str):
        self._edit_cat_counter += 1
        n = self._edit_cat_counter
        self._edit_cat_rows[n] = {}
        row = Horizontal(
            Input(id=f"ef_cv_{n}", value=value,
                  placeholder="e.g. android.intent.category.DEFAULT",
                  classes="ef_cat_input"),
            Button("✕", id=f"ef_crm_{n}", classes="ef_x_rm"),
            id=f"ef_cat_{n}", classes="ef_cat_row",
        )
        self.query_one("#ef_categories").mount(row)

    def _add_edit_extra_row(
        self,
        key: str,
        simple_type,
        value: str,
        is_new: bool,
        java_type: str = "",
        removable: bool = True,
    ):
        self._edit_extra_counter += 1
        n = self._edit_extra_counter
        self._edit_extra_rows[n] = {"key": key, "is_new": is_new, "type": simple_type or "string"}

        if is_new:
            selected_type = simple_type or "string"
            is_null = selected_type == "null"
            row = Horizontal(
                Input(id=f"ef_xk_{n}", value=key, placeholder="key", classes="ef_x_key_input"),
                Select(EXTRA_TYPE_OPTIONS, id=f"ef_xt_{n}", value=selected_type,
                       allow_blank=False, classes="ef_x_type_select"),
                Input(
                    id=f"ef_xv_{n}",
                    value="" if is_null else value,
                    placeholder=EXTRA_VALUE_PLACEHOLDERS[selected_type],
                    disabled=is_null,
                ),
                Button("✕", id=f"ef_xrm_{n}", classes="ef_x_rm"),
                id=f"ef_x_{n}", classes="ef_x_row",
            )
        else:
            editable = simple_type is not None and simple_type != "null"
            type_label = simple_type or java_type_display(java_type)
            row = Horizontal(
                Label(key, classes="ef_x_key_label"),
                Label(type_label, classes="ef_x_type_label"),
                Input(id=f"ef_xv_{n}", value=value, disabled=not editable),
                Button("✕", id=f"ef_xrm_{n}", classes="ef_x_rm", disabled=not removable),
                id=f"ef_x_{n}", classes="ef_x_row",
            )

        self.query_one("#ef_extras").mount(row)

    def _collect_edit_draft(self) -> dict:
        original = (self._current_intercepted_entry or {}).get("intent", {}) or {}
        draft = apply_mods_to_intent(original, [])
        draft["action"] = self.query_one("#ef_action", Input).value or None
        draft["data"] = self.query_one("#ef_data", Input).value or None

        categories = []
        for n in self._edit_cat_rows:
            value = self.query_one(f"#ef_cv_{n}", Input).value.strip()
            if not value:
                continue
            if value in categories:
                raise _EditValidationError(
                    f"Duplicate category: {value}",
                    f"#ef_cv_{n}",
                    title="Invalid category",
                )
            categories.append(value)
        draft["categories"] = categories

        extras = {}
        displayed_extras = self._edit_display_info.get("extras", {}) or {}
        for n, row_info in self._edit_extra_rows.items():
            if row_info["is_new"]:
                key = self.query_one(f"#ef_xk_{n}", Input).value.strip()
                extra_type = str(self.query_one(f"#ef_xt_{n}", Select).value)
                value = self.query_one(f"#ef_xv_{n}", Input).value
                if not key:
                    if value:
                        raise _EditValidationError(
                            "Extra key is required",
                            f"#ef_xk_{n}",
                        )
                    continue
            else:
                key = row_info["key"]
                extra_type = row_info["type"]
                value = self.query_one(f"#ef_xv_{n}", Input).value

            if key in extras:
                raise _EditValidationError(
                    f"Duplicate extra key: {key}",
                    f"#ef_xk_{n}" if row_info["is_new"] else f"#ef_xv_{n}",
                )

            snapshot = displayed_extras.get(key)
            if snapshot is not None and snapshot.get("editable") is False:
                extras[key] = copy.deepcopy(snapshot)
                continue

            displayed_value = "" if snapshot is None else str(snapshot.get("value", "") or "")
            if not row_info["is_new"] and snapshot is not None and value == displayed_value:
                extras[key] = copy.deepcopy(snapshot)
                continue

            error = validate_extra_value(extra_type, value)
            if error:
                raise _EditValidationError(
                    f"{key}: {error}",
                    f"#ef_xv_{n}",
                )
            rebuild_mods = []
            if snapshot is not None:
                rebuild_mods.append(("extra_rem", key, "", ""))
            rebuild_mods.append(("extra_add", key, value, extra_type))
            rebuilt = apply_mods_to_intent(
                {"extras": {key: snapshot} if snapshot is not None else {}},
                rebuild_mods,
            )
            extras[key] = rebuilt["extras"][key]
        draft["extras"] = extras

        flags_text = self.query_one("#ef_flags", Input).value.strip()
        flags = parse_flag_value(flags_text) if flags_text else 0
        if flags is None:
            raise _EditValidationError(
                "Flags must be a 32-bit integer or bit mask, for example 0x10000000",
                "#ef_flags",
                title="Invalid flags",
            )
        draft["flags"] = flags
        return draft

    def _collect_edit_mods(self) -> list:
        original = (self._current_intercepted_entry or {}).get("intent", {}) or {}
        return diff_intents(original, self._collect_edit_draft())

    def _forward_from_edit_mode(self):
        """Validate the form and keep it open until Frida confirms forwarding."""
        if not self._edit_mode or self._edit_forward_pending:
            return
        try:
            mods = self._collect_edit_mods()
        except _EditValidationError as error:
            self._show_edit_validation_error(error)
            return
        self._set_edit_forward_pending(True)
        self._apply_mods_and_forward_worker(mods)

    @work(thread=True)
    def _apply_mods_and_forward_worker(self, mods: list):
        try:
            if not self.frida_session or not self.frida_session.is_ready():
                self.call_from_thread(
                    self._restore_editor_after_forward_failure,
                    "Session not ready",
                )
                return
            decision_id = self._current_decision_id
            intent_id = self._current_intercept_id
            resolved = self._current_intercepted_entry
            all_mods = list(mods)
            if not self.frida_session.forward_with_mods(all_mods, decision_id):
                self.call_from_thread(
                    self._restore_editor_after_forward_failure,
                    "No matching intent is blocked to forward",
                )
                return
            self.set_intercept_state(False)
            self._finalize_forward(intent_id, resolved, all_mods)
        except Exception as e:
            self.call_from_thread(
                self._restore_editor_after_forward_failure,
                f"Modify and forward failed: {e}",
            )

    def _stage_current_mod(self, mod_type: str, key: str, val: str, extra_type: str = "") -> None:
        if self._current_intercepted_entry is None or self._current_intercept_id is None:
            self.write_cmd("[red]No intent blocked to modify[/red]")
            return
        mod = (mod_type, key, val, extra_type)
        if error := self._mod_safety_error(mod):
            self.write_cmd(f"[red]{error}[/red]")
            return
        self._staged_mods.append(mod)

    def _finalize_forward(self, intent_id: int | None, resolved_entry: dict | None, mods: list) -> None:
        entry = resolved_entry
        if entry is None and intent_id is not None:
            entry = next((e for e in self._all_intents if e["id"] == intent_id), None)

        if entry is not None and mods:
            apply_mods_to_entry(entry, mods)
            self._history_search_index[id(entry)] = history_search_text(entry)

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
        elif event.button.id in ("info_nav_overview", "info_nav_permissions", "info_nav_components"):
            self._switch_info_view(event.button.id)
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
                self._save_home_path(target, "")
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
        elif event.button.id == "btn_cancel_edit":
            self._exit_edit_mode()
            return
        elif event.button.id == "ef_add_extra":
            self._add_edit_extra_row("", None, "", is_new=True)
            return
        elif event.button.id == "ef_add_cat":
            self._add_edit_category_row("")
            return
        elif (event.button.id or "").startswith("ef_crm_"):
            n = int(event.button.id.split("_")[-1])
            self._edit_cat_rows.pop(n, None)
            try:
                self.query_one(f"#ef_cat_{n}").remove()
            except Exception:
                pass
            return
        elif (event.button.id or "").startswith("ef_xrm_"):
            n = int(event.button.id.split("_")[-1])
            self._edit_extra_rows.pop(n, None)
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
                column_widths=self._history_column_widths,
                on_widths_changed=self._on_history_column_widths_changed,
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
                        intercept_output.write(self._render_markup(render_intent_detail(
                            self._current_intercepted_entry,
                            show_stack=show,
                            stack_depth=depth,
                        )))
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
                            yield Input(
                                id="home_hooks_path",
                                value=self.db.load_hook_config_path(),
                                placeholder="additional hook definitions (.json)",
                                select_on_focus=False,
                            )
                            yield Button("Browse", id="home_hooks_browse")
                            yield Button("✕", id="home_hooks_clear")

                        with Horizontal(classes="connect_row"):
                            yield Label("Extra script", classes="connect_label")
                            yield Input(
                                id="home_script_path",
                                value=self.db.load_extra_script_path(),
                                placeholder="appended Frida agent (.js)",
                                select_on_focus=False,
                            )
                            yield Button("Browse", id="home_script_browse")
                            yield Button("✕", id="home_script_clear")

                        with Horizontal(classes="connect_row", id="home_anr_row"):
                            yield Label("Input ANR bypass (experimental)", id="home_anr_bypass_label")
                            yield Switch(value=False, id="home_system_anr_bypass")

                        yield Label("", id="home_error")
                        yield Rule()
                        with Horizontal(id="home_btn_row"):
                            yield Button("Connect", id="home_btn")
                            yield Button("Disconnect", id="home_disconnect", disabled=True)
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
                    Button("Cancel edit", id="btn_cancel_edit"),
                    Label("", id="intercept_header_spacer"),
                    Button("Filters", id="btn_intercept_filters"),
                    Button("Stack", id="btn_intercept_stack"),
                    id="intercept_header",
                )
                yield RichLog(id="intercept_output", markup=True, highlight=False, auto_scroll=False)
                with VerticalScroll(id="edit_form"):
                    yield Label("EDITING CAPTURED INTENT", id="ef_mode_label")
                    with Horizontal(classes="ef_row"):
                        yield Label("Action", classes="ef_label")
                        yield Input(id="ef_action", placeholder="e.g. android.intent.action.VIEW")
                    with Horizontal(classes="ef_row"):
                        yield Label("Data URI", classes="ef_label")
                        yield Input(id="ef_data", placeholder="e.g. https://example.com")
                    with Horizontal(classes="ef_row"):
                        yield Label("Flags", classes="ef_label")
                        yield Input(id="ef_flags", placeholder="e.g. 0x10000000")
                    yield Rule()
                    with Horizontal(classes="ef_section_header"):
                        yield Label("Categories", classes="ef_section")
                        yield Label("", classes="ef_section_spacer")
                        yield Button("+ Add", id="ef_add_cat")
                    yield Vertical(id="ef_categories")
                    yield Rule()
                    with Horizontal(classes="ef_section_header"):
                        yield Label("Extras", classes="ef_section")
                        yield Label("", classes="ef_section_spacer")
                        yield Button("+ Add", id="ef_add_extra")
                    with Horizontal(classes="ef_x_columns"):
                        yield Label("Key", classes="ef_x_key_header")
                        yield Label("Type", classes="ef_x_type_header")
                        yield Label("Value", classes="ef_x_value_header")
                        yield Label("", classes="ef_x_remove_header")
                    yield Vertical(id="ef_extras")
                yield RichLog(id="intercept_cmd_output", markup=True, highlight=False)
                yield OptionList(id="intercept_cmd_suggestions")
                yield Vertical(
                    Horizontal(
                        Label("❯", id="intercept_prompt_char"),
                        Input(
                            id="intercept_command_input",
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
            with TabPane(" Info app ", id="tab_info"):
                with Horizontal(id="info_split"):
                    with Vertical(id="info_rail"):
                        yield Button("Overview", id="info_nav_overview", classes="info-nav active")
                        yield Button("Permissions", id="info_nav_permissions", classes="info-nav")
                        yield Button("Components", id="info_nav_components", classes="info-nav")
                    with Vertical(id="info_main"):
                        yield Label("Connect to a target to inspect it.", id="info_empty")
                        with ContentSwitcher(initial="info_view_overview", id="info_switcher"):
                            with VerticalScroll(id="info_view_overview"):
                                yield RichLog(id="info_overview_log", markup=True, highlight=False, auto_scroll=False)
                            with Vertical(id="info_view_permissions"):
                                with Horizontal(classes="info_controls"):
                                    yield Input(id="info_perm_search", placeholder="Search permissions", select_on_focus=False)
                                    yield Select(
                                        [("All sources", "all"), ("requested", "requested"), ("defined", "defined")],
                                        id="info_perm_source", value="all", allow_blank=False,
                                    )
                                yield DataTable(id="info_perm_table", cursor_type="row")
                            with Vertical(id="info_view_components"):
                                with Horizontal(classes="info_controls"):
                                    yield Input(id="info_comp_search", placeholder="Search components", select_on_focus=False)
                                    yield Select(
                                        [("All types", "all"), ("activity", "activity"), ("service", "service"),
                                         ("receiver", "receiver"), ("provider", "provider")],
                                        id="info_comp_type", value="all", allow_blank=False,
                                    )
                                    with Horizontal(id="info_exposed_group", classes="switch-control"):
                                        yield Switch(value=False, id="info_comp_exposed")
                                        yield Label("Exposed only", classes="switch-control-label")
                                yield DataTable(id="info_comp_table", cursor_type="row")
                                yield RichLog(id="info_comp_detail", markup=True, highlight=False, auto_scroll=False)
            with TabPane(" Log ", id="tab_log"):
                with Horizontal(id="log_header"):
                    with Horizontal(id="log_verbose_group", classes="switch-control"):
                        yield Switch(value=self._log_verbose, id="log_verbose")
                        yield Label("Verbose logs", id="log_verbose_label", classes="switch-control-label")
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
                    yield Button("Save", id="settings_save")
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
            "btn_cancel_edit",
            "btn_intercept_filters",
            "btn_intercept_stack",
            "btn_history_filters",
            "btn_history_stack",
            "btn_columns",
        ):
            self.query_one(f"#{btn_id}", Button).active_effect_duration = 0
        self._apply_command_bar_visibility()
        self._refresh_history_table()
        self._init_info_tab()
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
                if widget_id == "home_hooks_path":
                    path = str(Path(path).expanduser().resolve())
                self.query_one(f"#{widget_id}", Input).value = path
                if widget_id == "home_hooks_path":
                    try:
                        load_hook_config(path)
                    except HookConfigError as error:
                        self._show_hook_config_error(error)
                        return
                    self.query_one("#home_error", Label).update("")
                self._save_home_path(widget_id, path)
            except Exception:
                pass

    def _show_hook_config_error(self, error: HookConfigError) -> None:
        message = f"Hook config: {error.details[0]}"
        self.query_one("#home_error", Label).update(message)
        for detail in error.details:
            self.write_log(log_error(f"{error.label}: {detail}", "loader"))
        self.notify(message, severity="error", timeout=6)

    def _save_home_path(self, widget_id: str, path: str) -> None:
        if widget_id == "home_hooks_path":
            self.db.save_hook_config_path(path)
        elif widget_id == "home_script_path":
            self.db.save_extra_script_path(path)

    def _save_home_paths(self, hooks_path: str, script_path: str) -> None:
        self.db.save_hook_config_path(hooks_path)
        self.db.save_extra_script_path(script_path)

    def _try_connect(self):
        device_id = self.query_one("#home_device", Select).value
        if not getattr(self, "_home_devices", []) or is_select_empty(device_id):
            self.query_one("#home_error", Label).update("No device available")
            return

        mode = self.query_one("#home_mode", Select).value
        target_val = self.query_one("#home_target_select", Select).value
        if is_select_empty(target_val):
            self.query_one("#home_error", Label).update("Select a target")
            return
        target = str(target_val)

        self.query_one("#home_error", Label).update("")

        hooks_path_raw = self.query_one("#home_hooks_path", Input).value.strip()
        script_path_raw = self.query_one("#home_script_path", Input).value.strip()
        if hooks_path_raw:
            hooks_path_raw = str(Path(hooks_path_raw).expanduser().resolve())
            self.query_one("#home_hooks_path", Input).value = hooks_path_raw
        hooks_path = hooks_path_raw or None
        try:
            validated_hooks = load_hook_config(hooks_path)
        except HookConfigError as error:
            self._show_hook_config_error(error)
            return

        if self.frida_session:
            self.frida_session.cleanup()
            self.frida_session = None

        self._startup_messages.clear()
        self.set_intercept_state(False)

        self._save_home_paths(hooks_path_raw, script_path_raw)
        script_path = script_path_raw or None
        self._init_session(SessionConfig(
            spawn_package=target if mode == "f" else None,
            attach_name=target if mode == "n" else None,
            attach_pid=int(target) if mode == "p" else None,
            custom_hooks=hooks_path,
            validated_hooks=validated_hooks,
            extra_script=script_path,
        ))
        for msg in self._startup_messages:
            self.write_log(msg)
        self._refresh_history_table()

        self.on_device_selected(device_id)

    def on_select_changed(self, event: Select.Changed):
        if event.select.id in ("home_device", "home_mode"):
            self._populate_target_apps()
        elif event.select.id == "info_perm_source":
            self._refresh_info_permissions()
        elif event.select.id == "info_comp_type":
            self._refresh_info_components()
        elif (event.select.id or "").startswith("ef_xt_"):
            n = event.select.id.rsplit("_", 1)[-1]
            try:
                value_input = self.query_one(f"#ef_xv_{n}", Input)
                extra_type = str(event.value)
                is_null = extra_type == "null"
                value_input.disabled = is_null
                value_input.placeholder = EXTRA_VALUE_PLACEHOLDERS.get(extra_type, "value")
                if is_null:
                    value_input.value = ""
            except Exception:
                pass

    def on_device_selected(self, device_id):
        if not device_id:
            self.write_cmd("[red]No device selected[/red]")
            self.exit()
            return

        cfg = self._session_config
        target = cfg.target_label()
        self._connection_generation += 1
        self._connection_state = "connecting"
        self._session_device_id = device_id
        self._session_api_level = None
        self.query_one("#session_bar").remove_class("connection-error")
        self.query_one("#session_bar").remove_class("connected")
        self.query_one("#session_bar").add_class("connecting")
        self.query_one("#session_info", Label).update(f"Connecting to {target}  ·  {device_id}…")
        self.query_one("#home_btn", Button).label = "Connecting…"
        self.query_one("#home_btn", Button).disabled = True
        self.query_one("#home_disconnect", Button).disabled = True

        self.db.set_info("target", target)
        self.db.set_info("device_id", device_id)

        session = self.frida_session
        session.api_level_cb = lambda sdk_int, session=session: self._on_api_level(sdk_int, session)
        session.hook_warning_cb = (
            lambda message, session=session: self._on_hook_warning(message, session)
        )
        session.connected_cb = lambda session=session: self._on_connected(session)
        session.connection_failed_cb = (
            lambda stage, error, session=session: self._on_connection_failed(stage, error, session)
        )
        session.disconnected_cb = lambda session=session: self._on_disconnected(session)
        session.connect(device_id)

    def _on_hook_warning(self, message: str, session=None) -> None:
        if session is not None and session is not self.frida_session:
            return

        def _do():
            if session is None or session is self.frida_session:
                self.notify(message, severity="warning", timeout=6)

        if threading.current_thread() is threading.main_thread():
            _do()
        else:
            self.call_from_thread(_do)

    def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id == "info_comp_exposed":
            self._refresh_info_components()
            return
        if event.switch.id == "log_verbose":
            self._log_verbose = event.value
            self._refresh_log_output()
            return

        if event.switch.id != "home_system_anr_bypass":
            return
        self._system_anr_bypass_enabled = event.value
        if event.value and self._connection_state == "connected" and self._session_device_id:
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
            candidates = enumerate_preferred_devices(frida)
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
                    self.query_one("#home_error", Label).update(f"Devices: {error}")
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
                    self.query_one("#home_error", Label).update(f"Apps: {error}")
                except Exception:
                    pass
            self.call_from_thread(_err)

    def _on_api_level(self, sdk_int, session=None):
        if session is not None and session is not self.frida_session:
            return
        self._session_api_level = sdk_int
        def _do():
            if self._connection_state == "connected":
                target = self._session_config.target_label()
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
        self._connection_state = "connected"
        def _do():
            try:
                target = self._session_config.target_label()
                api = f"  ·  API {self._session_api_level}" if self._session_api_level is not None else ""
                self.query_one("#session_info", Label).update(
                    f"{target}  ·  {self._session_device_id}{api}"
                )
                self.query_one("#session_bar").remove_class("connection-error")
                self.query_one("#session_bar").remove_class("connecting")
                self.query_one("#session_bar").add_class("connected")
                self.query_one("#home_btn", Button).label = "Connect"
                self.query_one("#home_btn", Button).disabled = True
                self.query_one("#home_disconnect", Button).disabled = False
                self.query_one("#home_error", Label).update("")
                self.query_one("#main_tabs", TabbedContent).active = "tab_intercept"
            except Exception:
                pass
            if self._system_anr_bypass_enabled:
                self._ensure_system_anr_bypass(self._session_device_id)
            self._fetch_app_info_worker()
        try:
            self.call_from_thread(_do)
        except Exception:
            pass

    @staticmethod
    def _connection_failure_message(stage: str, error: Exception) -> str:
        error_name = type(error).__name__
        if error_name == "ServerNotRunningError":
            return "Connection failed. Frida server is not running or cannot be reached."
        if error_name == "ProcessNotFoundError":
            return "Connection failed. The target process was not found."
        if error_name in ("ExecutableNotFoundError", "ExecutableNotSupportedError") or stage == "spawn":
            return "Connection failed. The target application could not be spawned."
        if error_name == "PermissionDeniedError":
            return "Connection failed. Frida does not have permission to attach to the target."
        if error_name == "TimedOutError":
            return "Connection failed. The selected device did not respond in time."
        if error_name in ("TransportError", "ProtocolError"):
            return "Connection failed. Communication with the selected device was lost."
        if stage == "configuration":
            return "Connection failed. The hook configuration is invalid."
        if stage in ("agent", "hooks", "resume"):
            return "Connection failed. The target was reached, but the noxen agent could not start."
        return "Connection failed. See Log for technical details."

    def _on_connection_failed(self, stage, error, session=None):
        if session is not None and session is not self.frida_session:
            return
        message = self._connection_failure_message(stage, error)
        self.frida_session = None
        self._connection_state = "disconnected"
        self._session_device_id = ""
        self._session_api_level = None
        self._cleanup_system_server_session(async_cleanup=True)
        generation = self._connection_generation

        def _do():
            if generation != self._connection_generation:
                return
            self.set_intercept_state(False)
            try:
                self.query_one("#session_bar").remove_class("connecting")
                self.query_one("#session_bar").remove_class("connected")
                self.query_one("#session_bar").add_class("connection-error")
                self.query_one("#session_info", Label).update("Not connected")
                self.query_one("#home_btn", Button).label = "Connect"
                self.query_one("#home_btn", Button).disabled = False
                self.query_one("#home_disconnect", Button).disabled = True
                self.query_one("#home_error", Label).update(message)
            except Exception:
                pass
            self._clear_intercept_output()
            self._clear_info_tab()
            self.notify(message, severity="error", timeout=6)
            self.set_timer(3, lambda: self._clear_session_error_state(generation))

        try:
            self.call_from_thread(_do)
        except Exception:
            pass

    def _on_disconnected(self, session=None):
        if session is not None and session is not self.frida_session:
            return
        self.frida_session = None
        self._connection_state = "disconnected"
        self._session_device_id = ""
        self._session_api_level = None
        self._cleanup_system_server_session(async_cleanup=True)
        generation = self._connection_generation

        def _do():
            if generation != self._connection_generation:
                return
            self.set_intercept_state(False)
            try:
                self.query_one("#session_bar").remove_class("connection-error")
                self.query_one("#session_bar").remove_class("connecting")
                self.query_one("#session_bar").remove_class("connected")
                self.query_one("#session_info", Label).update("Not connected")
                self.query_one("#home_btn", Button).label = "Connect"
                self.query_one("#home_btn", Button).disabled = False
                self.query_one("#home_disconnect", Button).disabled = True
            except Exception:
                pass
            self._clear_intercept_output()
            self._clear_info_tab()
        try:
            self.call_from_thread(_do)
        except Exception:
            pass

    def _do_disconnect(self):
        if self.frida_session:
            self.frida_session.cleanup()
            self.frida_session = None
        self._connection_state = "disconnected"
        self._session_device_id = ""
        self._session_api_level = None
        self._cleanup_system_server_session()
        self.set_intercept_state(False)
        try:
            self.query_one("#session_bar").remove_class("connection-error")
            self.query_one("#session_bar").remove_class("connecting")
            self.query_one("#session_bar").remove_class("connected")
            self.query_one("#session_info", Label).update("Not connected")
            self.query_one("#home_btn", Button).label = "Connect"
            self.query_one("#home_btn", Button).disabled = False
            self.query_one("#home_disconnect", Button).disabled = True
        except Exception:
            pass
        self._clear_intercept_output()
        self._clear_info_tab()

    def _clear_session_error_state(self, generation: int | None = None) -> None:
        if (
            self._connection_state != "disconnected"
            or (
                generation is not None
                and generation != self._connection_generation
            )
        ):
            return
        try:
            self.query_one("#session_bar").remove_class("connection-error")
        except Exception:
            pass

    # --- Info app tab ---

    def _init_info_tab(self) -> None:
        self._set_info_columns("info_perm_table")
        self._set_info_columns("info_comp_table")
        self.query_one("#info_switcher", ContentSwitcher).display = False

    def _switch_info_view(self, nav_id: str) -> None:
        mapping = {
            "info_nav_overview": "info_view_overview",
            "info_nav_permissions": "info_view_permissions",
            "info_nav_components": "info_view_components",
        }
        view = mapping.get(nav_id)
        if not view:
            return
        self.query_one("#info_switcher", ContentSwitcher).current = view
        for button in self.query(".info-nav"):
            button.set_class(button.id == nav_id, "active")

    def action_info_refresh(self) -> None:
        self._fetch_app_info_worker()

    def action_info_toggle_rail(self) -> None:
        rail = self.query_one("#info_rail")
        rail.display = not rail.display

    @work(thread=True, exclusive=True, group="app_info")
    def _fetch_app_info_worker(self) -> None:
        # Connect fires right after resume; in spawn mode the app's Application context
        # may not exist yet, so poll a few times until the snapshot is ready.
        worker = get_current_worker()
        for _ in range(8):
            if worker.is_cancelled:
                return
            session = self.frida_session
            if session is None or not session.is_ready():
                return
            try:
                info = session.get_app_info()
            except Exception:
                info = None
            if info and not info.get("error") and (info.get("identity") or {}).get("package"):
                self.call_from_thread(self._apply_app_info, info)
                return
            time.sleep(0.4)
        self.call_from_thread(
            self.write_log, log_warning("App info not ready yet — use Refresh", "info")
        )

    def _apply_app_info(self, info: dict) -> None:
        self._app_info = info
        try:
            self.query_one("#info_empty", Label).display = False
            self.query_one("#info_switcher", ContentSwitcher).display = True
            overview = self.query_one("#info_overview_log", RichLog)
            overview.clear()
            overview.write(self._render_markup(render_overview(info)))
            overview.scroll_home(animate=False)
            self._refresh_info_permissions()
            self._refresh_info_components()
        except Exception:
            pass

    def _refresh_info_permissions(self) -> None:
        if not self._app_info:
            return
        source = self.query_one("#info_perm_source", Select).value
        source = None if source == "all" else source
        query = self.query_one("#info_perm_search", Input).value.strip()
        column, reverse = self._info_sort["info_perm_table"]
        perms = filter_permissions(self._app_info.get("permissions"), query=query, source=source)
        table = self._set_info_columns("info_perm_table")
        for perm in sort_permissions(perms, column, reverse):
            table.add_row(*permission_row(perm))

    def _refresh_info_components(self) -> None:
        if not self._app_info:
            return
        type_value = self.query_one("#info_comp_type", Select).value
        type_filter = None if type_value == "all" else type_value
        exposed = self.query_one("#info_comp_exposed", Switch).value
        query = self.query_one("#info_comp_search", Input).value.strip()
        column, reverse = self._info_sort["info_comp_table"]
        comps = sort_components(
            filter_components(self._app_info.get("components"), query=query,
                              type_filter=type_filter, exposed_only=exposed),
            column, reverse,
        )
        table = self._set_info_columns("info_comp_table")
        for comp in comps:
            table.add_row(*component_row(comp), key=comp.get("name"))
        # Keep the selected component (and its detail) across re-sorts and filter changes.
        index = next((i for i, c in enumerate(comps) if c.get("name") == self._info_selected_component), None)
        if index is None:
            self._info_selected_component = None
            self.query_one("#info_comp_detail", RichLog).clear()
        else:
            table.move_cursor(row=index, animate=False)

    def _set_info_columns(self, table_id: str) -> DataTable:
        """Rebuild an Info app table's columns (and clear its rows), marking the sort column."""
        table = self.query_one(f"#{table_id}", DataTable)
        column, reverse = self._info_sort[table_id]
        specs = COMPONENT_COLUMNS if table_id == "info_comp_table" else PERMISSION_COLUMNS
        table.clear(columns=True)
        for key, label in specs:
            indicator = (" ↓" if reverse else " ↑") if key == column else ""
            table.add_column(label + indicator, key=key)
        return table

    def _clear_info_tab(self) -> None:
        self._app_info = None
        self._info_selected_component = None
        try:
            self.query_one("#info_switcher", ContentSwitcher).display = False
            self.query_one("#info_empty", Label).display = True
            for widget_id in ("#info_perm_table", "#info_comp_table"):
                self.query_one(widget_id, DataTable).clear()
            for widget_id in ("#info_comp_detail", "#info_overview_log"):
                self.query_one(widget_id, RichLog).clear()
        except Exception:
            pass

    def _write_rich(self, widget_id: str, text: str, notify: bool = False) -> None:
        plain = re.sub(r"\[/?[^\]]*\]", "", text).strip() if notify else ""

        def _do():
            try:
                self.query_one(f"#{widget_id}", RichLog).write(self._render_markup(text))
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
                        output.write(app_markup_renderable(self, entry))
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
        self._history_search_index[id(entry)] = history_search_text(entry)
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
        colors = semantic_colors(self.current_theme.dark)
        row_vals = history_row_values(
            entry,
            self._history_visible_cols,
            _HISTORY_COLUMNS,
            colors.success,
            colors.error,
        )
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

    def _on_history_column_widths_changed(self, widths: dict):
        """Save history column widths to DB and refresh table."""
        self._history_column_widths = normalize_history_column_widths(widths)
        self.db.save_history_column_widths(self._history_column_widths)
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
            self._history_search_index,
        )

    def _fill_table_rows(self, table, filtered):
        """Add rows to table from a filtered+sorted entry list."""
        colors = semantic_colors(self.current_theme.dark)
        for entry in filtered:
            row_vals = history_row_values(
                entry,
                self._history_visible_cols,
                _HISTORY_COLUMNS,
                colors.success,
                colors.error,
            )
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
            table.add_column(label + indicator, key=key, width=self._history_column_widths.get(key))

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
        rendered = app_markup_renderable(self,
            render_intent_detail(entry, show_stack=self.show_stack, stack_depth=self.stack_depth)
        )

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
        if event.data_table.id == "info_comp_table":
            if event.row_key is None or event.row_key.value is None:
                return
            name = event.row_key.value
            self._info_selected_component = name
            comp = next(
                (c for c in (self._app_info or {}).get("components", []) if c.get("name") == name),
                None,
            )
            if comp:
                try:
                    detail = self.query_one("#info_comp_detail", RichLog)
                    detail.clear()
                    own_package = ((self._app_info or {}).get("identity") or {}).get("package")
                    detail.write(self._render_markup(render_component_detail(comp, own_package)))
                    detail.scroll_home(animate=False)
                except Exception:
                    pass
            return
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
                detail.write(self._render_markup(render_intent_detail(
                    entry,
                    show_stack=self._history_show_stack,
                    stack_depth=self._history_stack_depth,
                )))
                detail.scroll_home(animate=False)
            except Exception:
                pass

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected):
        table_id = event.data_table.id
        if table_id in self._info_sort:
            column, reverse = self._info_sort[table_id]
            key = event.column_key.value
            self._info_sort[table_id] = (key, not reverse) if key == column else (key, False)
            if table_id == "info_comp_table":
                self._refresh_info_components()
            else:
                self._refresh_info_permissions()
            return
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
        self._intent_blocked = bool(is_intercepted)

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
                self.refresh_bindings()
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
        self._history_search_index.clear()
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
        intercept_blocked = (
            self._active_tab == "tab_intercept"
            and self._intent_blocked
            and not self.screen.is_modal
        )
        if action == "forward_current":
            return intercept_blocked and not self._edit_mode
        if action == "drop_current":
            return intercept_blocked and not self._edit_forward_pending
        if action in ("apply_edit", "cancel_edit"):
            return intercept_blocked and self._edit_mode and not self._edit_forward_pending
        if action in ("info_refresh", "info_toggle_rail"):
            return self._active_tab == "tab_info"
        if action == "clear_log":
            return self._active_tab in ("tab_log", "tab_history")
        if action == "toggle_command_bar":
            return self._active_tab in ("tab_history", "tab_intercept")
        if action in ("resize_panel_up", "resize_panel_down"):
            if self._active_tab == "tab_intercept":
                return True if self._intercept_command_bar_visible else None
            return self._active_tab == "tab_history"
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

    def action_apply_edit(self):
        self._forward_from_edit_mode()

    def action_forward_current(self):
        self.process_command_worker("forward")

    def action_drop_current(self):
        self.process_command_worker("drop")

    def action_cancel_edit(self):
        self._exit_edit_mode()

    def on_key(self, event):
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
        if inp_id == "info_perm_search":
            self._refresh_info_permissions()
            return
        if inp_id == "info_comp_search":
            self._refresh_info_components()
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

    def _handle_slash_command(self, cmd_base: str, parts: list, write_fn=None, raw_command=None):
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

        elif cmd_base == "/search" and self._active_tab == "tab_history":
            parsed = parse_search_command(raw_command or " ".join(parts))
            if parsed is None:
                write_fn("[red]Usage: /search <text> | /search[/red]")
                return
            self.call_from_thread(self._set_history_search, parsed.query)

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
            self._handle_slash_command(
                parsed.base,
                parsed.parts,
                write_fn=self._write_history_command,
                raw_command=parsed.raw,
            )
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

    def _set_history_search(self, query: str) -> None:
        self.query_one("#history_search", Input).value = query

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
            if self._edit_mode:
                try:
                    mods = self.call_from_thread(self._collect_edit_mods)
                except _EditValidationError as error:
                    self.call_from_thread(self._show_edit_validation_error, error)
                    write_fn(f"[red]{error}[/red]")
                    return
            else:
                mods = list(self._staged_mods)
            if not self.frida_session.intercept_off_with_mods(
                mods, self._current_decision_id
            ):
                write_fn("[red]Could not disable interception for the active intent[/red]")
                return
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
            detail.write(self._render_markup(render_intent_detail(
                self._history_selected_entry,
                show_stack=self._history_show_stack,
                stack_depth=self._history_stack_depth,
            )))
            detail.scroll_home(animate=False)
        except Exception:
            pass

    def _refresh_intercept_display(self):
        if self._current_intercepted_entry is None:
            return
        try:
            intercept_output = self.query_one("#intercept_output", RichLog)
            intercept_output.clear()
            intercept_output.write(self._render_markup(render_intent_detail(
                self._current_intercepted_entry,
                show_stack=self.show_stack,
                stack_depth=self.stack_depth,
            )))
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
                self._handle_slash_command(cmd_base, parts, raw_command=parsed.raw)
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
                if not self.frida_session.forward_with_mods(
                    mods, self._current_decision_id
                ):
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
                    if self._edit_mode:
                        error = self.call_from_thread(
                            self._apply_command_mod_to_editor, mod
                        )
                        if error:
                            self.write_cmd(f"[red]{error}[/red]")
                    else:
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
                    colors = semantic_colors(self.current_theme.dark)
                    table.update_cell(
                        str(intent_id),
                        "outcome",
                        history_outcome_cell(outcome, colors.success, colors.error),
                    )
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
            self.frida_session.connection_failed_cb = None
            self.frida_session.disconnected_cb = None
            self.frida_session.cleanup()
        self._cleanup_system_server_session()
        if self.db:
            self.db.close()
