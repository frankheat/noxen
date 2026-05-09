from pathlib import Path

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    DirectoryTree,
    Input,
    Label,
    ListItem,
    ListView,
    Rule,
    Select,
    Switch,
)

from noxen.filters import FilterManager
from noxen.textual_compat import is_select_empty


class _VisibleTree(DirectoryTree):
    def filter_paths(self, paths):
        return [p for p in paths if not p.name.startswith(".")]


class FileBrowserModal(ModalScreen):
    CSS = """
    FileBrowserModal { align: center middle; }
    #fbm_dialog {
        width: 70;
        height: 30;
        background: $surface;
        border: solid $panel-lighten-2;
        padding: 1 2;
    }
    #fbm_title {
        text-style: bold;
        color: #26a368;
        margin-bottom: 1;
    }
    #fbm_tree {
        height: 1fr;
        border: solid #2C3E3A;
        margin-bottom: 1;
    }
    #fbm_selected {
        height: 1;
        color: $text-muted;
        margin-bottom: 1;
    }
    #fbm_buttons {
        height: 3;
        align: right middle;
    }
    #fbm_buttons Button {
        width: auto;
        height: 3;
        border: round $panel-lighten-2;
        padding: 0 2;
        background: transparent;
        text-style: bold;
        margin-left: 1;
    }
    #fbm_ok:hover, #fbm_ok:focus {
        border: round #26a368;
        color: #26a368;
        background-tint: $surface 0%;
    }
    #fbm_cancel:hover, #fbm_cancel:focus {
        border: round $panel-lighten-2;
        background-tint: $surface 0%;
    }
    """

    def __init__(self, title: str):
        super().__init__()
        self._title = title
        self._selected_path: str | None = None

    def compose(self) -> ComposeResult:
        start = Path(Path.cwd().anchor)
        with Vertical(id="fbm_dialog"):
            yield Label(self._title, id="fbm_title")
            yield _VisibleTree(str(start), id="fbm_tree")
            yield Label("No file selected", id="fbm_selected")
            with Horizontal(id="fbm_buttons"):
                yield Button("Cancel", id="fbm_cancel")
                yield Button("Select", id="fbm_ok", disabled=True)

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        self._selected_path = str(event.path)
        try:
            self.query_one("#fbm_selected", Label).update(f"[dim]{event.path.name}[/dim]")
            self.query_one("#fbm_ok", Button).disabled = False
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "fbm_ok" and self._selected_path:
            self.dismiss(self._selected_path)
        else:
            self.dismiss(None)


class ColumnSelectModal(ModalScreen):
    CSS = """
    Button { text-style: bold; }
    ColumnSelectModal { align: center middle; }
    #csm_dialog {
        width: 36;
        height: auto;
        max-height: 90%;
        background: $surface;
        border: solid $panel-lighten-2;
        padding: 0 2 1 2;
    }
    #csm_topbar { dock: top; height: 1; align: right middle; }
    #csm_btn_close { height: 1; border: none; padding: 0; width: auto; min-width: 1; }
    #csm_title { width: 100%; content-align: center middle; text-style: bold; margin-bottom: 1; }
    #csm_list { height: auto; max-height: 20; border: solid $panel; margin-top: 1; }
    #csm_list > ListItem { padding: 0 1; }
    """

    def __init__(self, visible_cols: set, on_changed: callable, columns: list[tuple[str, str]]):
        super().__init__()
        self._visible = set(visible_cols)
        self._on_changed = on_changed
        self._columns = columns

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="csm_dialog"):
            with Horizontal(id="csm_topbar"):
                yield Button("✕", id="csm_btn_close")
            yield Label("Columns", id="csm_title")
            yield ListView(id="csm_list")

    def on_mount(self):
        lv = self.query_one("#csm_list", ListView)
        for key, label in self._columns:
            vis = "✓ " if key in self._visible else "○ "
            lv.append(ListItem(Label(vis + (label or key))))

    def _rebuild(self):
        items = list(self.query_one("#csm_list", ListView).query("ListItem"))
        for i, (key, label) in enumerate(self._columns):
            vis = "✓ " if key in self._visible else "○ "
            items[i].query_one(Label).update(vis + (label or key))

    def on_list_view_selected(self, event: ListView.Selected):
        if event.list_view.id != "csm_list":
            return
        idx = self.query_one("#csm_list", ListView).index
        if idx is None or idx >= len(self._columns):
            return
        col_key = self._columns[idx][0]
        if col_key in self._visible:
            if len(self._visible) > 1:
                self._visible.discard(col_key)
        else:
            self._visible.add(col_key)
        self._rebuild()
        self._on_changed(set(self._visible))

    def on_button_pressed(self, event: Button.Pressed):
        event.stop()
        if event.button.id == "csm_btn_close":
            self.dismiss()


class HelpModal(ModalScreen):
    CSS = """
    HelpModal { align: center middle; }
    #help_dialog {
        width: 90%;
        max-width: 90;
        min-width: 40;
        height: auto;
        max-height: 65%;
        background: $surface;
        border: solid $panel-lighten-2;
        padding: 0 2 1 2;
    }
    #help_topbar {
        dock: top;
        height: 1;
        align: right middle;
    }
    #help_close { height: 1; border: none; padding: 0; width: auto; min-width: 1; }
    #help_title {
        width: 100%;
        content-align: center middle;
        text-style: bold;
        margin-bottom: 1;
    }
    """

    def __init__(self, menu):
        super().__init__()
        self._menu = menu

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="help_dialog"):
            with Horizontal(id="help_topbar"):
                yield Button("✕", id="help_close")
            yield Label("Help", id="help_title")
            for category, cmds in self._menu.items():
                yield Label(f"\n{category.upper()}", classes="hfm_section")
                for command, desc in cmds:
                    yield Label(f"    {command:<28} {desc}")
            yield Label("")

    def on_button_pressed(self, event: Button.Pressed):
        event.stop()
        self.dismiss()

    def on_key(self, event):
        event.stop()
        self.dismiss()


class StackModal(ModalScreen):
    CSS = """
    Button { text-style: bold; }
    StackModal { align: center middle; }
    #sm_dialog {
        width: 40;
        height: auto;
        background: $surface;
        border: solid $panel-lighten-2;
        padding: 0 2 1 2;
    }
    #sm_topbar { dock: top; height: 1; align: right middle; }
    #sm_close { height: 1; border: none; padding: 0; width: auto; min-width: 1; text-style: bold }
    #sm_title { width: 100%; content-align: center middle; text-style: bold; margin-bottom: 1; }
    #sm_toggle_row { height: auto; align: left middle; margin-top: 1; }
    #sm_toggle_row Label { width: auto; margin-right: 1; }
    #sm_toggle { width: auto; border: none; }
    #sm_depth_row { height: auto; align: left middle; margin-top: 1; }
    #sm_depth_row Label { width: auto; margin-right: 1; }
    #sm_depth_input { width: 1fr; height: 1; }
    #sm_error { height: 1; margin-top: 1; }
    #sm_footer { height: 3; align: right middle; margin-top: 1; }
    #sm_save {
        height: 3;
        border: round #26a368;
        background: transparent;
        color: #26a368;
        padding: 0 1;
        width: auto;
    }
    #sm_save:hover, #sm_save:focus {
        border: round #26a368;
        background: transparent;
        color: #26a368;
        background-tint: $surface 0%;
    }
    """

    def __init__(self, show_stack: bool, depth: int, on_confirm: callable):
        super().__init__()
        self._show_stack = show_stack
        self._depth = depth
        self._on_confirm = on_confirm

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="sm_dialog"):
            with Horizontal(id="sm_topbar"):
                yield Button("✕", id="sm_close")
            yield Label("Stack Trace", id="sm_title")
            with Horizontal(id="sm_toggle_row"):
                yield Label("Show stack:")
                yield Switch(value=self._show_stack, id="sm_toggle")
            with Horizontal(id="sm_depth_row"):
                yield Label("Depth:")
                yield Input(value=str(self._depth), id="sm_depth_input")
            yield Label("", id="sm_error")
            with Horizontal(id="sm_footer"):
                yield Button("Save", id="sm_save", variant="primary")

    def on_button_pressed(self, event: Button.Pressed):
        event.stop()
        if event.button.id in ("sm_close", "sm_save"):
            self._apply()
            self.dismiss()

    def on_key(self, event):
        if event.key == "escape":
            self._apply()
            self.dismiss()

    def _apply(self):
        show = self.query_one("#sm_toggle", Switch).value
        try:
            depth = int(self.query_one("#sm_depth_input", Input).value.strip())
            if depth < 1:
                raise ValueError
        except (ValueError, Exception):
            depth = self._depth
        self._on_confirm(show, depth)


class FilterModal(ModalScreen):
    CSS = """
    Button { text-style: bold; }
    FilterModal { align: center middle; }
    #hfm_dialog {
        width: 90%;
        max-width: 95;
        min-width: 40;
        height: auto;
        max-height: 90%;
        background: $surface;
        border: solid $panel-lighten-2;
        padding: 0 2 1 2;
    }
    #hfm_topbar {
        dock: top;
        height: 1;
        align: right middle;
    }
    #hfm_btn_close { height: 1; border: none; padding: 0; width: auto; min-width: 1; }
    #hfm_title {
        width: 100%;
        content-align: center middle;
        text-style: bold;
        margin-bottom: 1;
    }
    .hfm_section { color: $text; margin-top: 1; text-style: bold; }
    FilterModal Rule { color: $text-muted; margin: 1 0; }
    #hfm_filters_table {
        height: auto;
        max-height: 10;
        border: solid $panel;
        margin-top: 1;
    }
    #hfm_remove_row { height: auto; margin-top: 1; }
    #hfm_remove_row Button { height: 1; border: none; padding: 0 1; }
    #hfm_type_row   { height: auto; margin-top: 1; align: left middle; }
    #hfm_type_row Label { width: auto; margin-right: 1; content-align: left middle; }
    #hfm_sel_type { height: 1; }
    #hfm_sel_type > SelectCurrent { border: none; height: 1; padding: 0 1; }
    #hfm_pairs_container { height: auto; margin-top: 1; }
    .hfm_pair_row { height: 1; margin-bottom: 1; align: left middle; }
    .hfm_pair_label { width: auto; margin-right: 1; content-align: left middle; }
    .hfm_pair_sel { height: 1; }
    .hfm_pair_sel > SelectCurrent { border: none; height: 1; padding: 0 1; }
    .hfm_pair_row Input { width: 1fr; }
    .hfm_pair_rm { width: 3; height: 1; border: none; min-width: 3; }
    #hfm_add_ctrl { height: auto; margin-top: 1; align: left middle; }
    #hfm_add_ctrl_spacer { width: 1fr; }
    #hfm_btn_add_pair {
        height: 3;
        border: round $panel-lighten-2;
        background: transparent;
        padding: 0 1;
    }
    #hfm_btn_add_pair:hover, #hfm_btn_add_pair:focus {
        border: round $accent;
        background: transparent;
        background-tint: $surface 0%;
    }
    #hfm_btn_add_filter {
        height: 3;
        border: round #26a368;
        background: transparent;
        color: #26a368;
        padding: 0 1;
    }
    #hfm_btn_add_filter:hover, #hfm_btn_add_filter:focus {
        border: round #26a368;
        background: transparent;
        color: #26a368;
        background-tint: $surface 0%;
    }
    #hfm_status { height: 1; margin-top: 1; }
    #hfm_filters_table:focus { border: solid $panel; background-tint: $surface 0%; }
    """

    VALID_KEYS = sorted(FilterManager.VALID_KEYS)
    TYPE_OPTIONS = [("ignore", "ignore"), ("focus", "focus")]
    SELECT_CHROME_WIDTH = 6

    def __init__(self, filter_manager: FilterManager, on_filters_changed: callable, title: str = "Filters"):
        super().__init__()
        self._fm = filter_manager
        self._on_filters_changed = on_filters_changed
        self._title = title
        self._selected_filter_id: int | None = None
        self._pair_counter = 0
        self._active_pairs: list[int] = []

    @classmethod
    def _option_width(cls, options) -> int:
        return max(len(str(label)) for label, _value in options) + cls.SELECT_CHROME_WIDTH

    @classmethod
    def _fit_select_width(cls, select: Select, options) -> Select:
        width = cls._option_width(options)
        select.styles.width = width
        select.styles.min_width = width
        return select

    def compose(self) -> ComposeResult:
        type_select = Select(
            self.TYPE_OPTIONS,
            id="hfm_sel_type",
            value="ignore",
            allow_blank=False,
        )
        self._fit_select_width(type_select, self.TYPE_OPTIONS)
        with VerticalScroll(id="hfm_dialog"):
            with Horizontal(id="hfm_topbar"):
                yield Button("✕", id="hfm_btn_close")
            yield Label(self._title, id="hfm_title")
            yield Label("Active filters", classes="hfm_section")
            yield DataTable(id="hfm_filters_table", cursor_type="row")
            with Horizontal(id="hfm_remove_row"):
                yield Button("Remove selected", id="hfm_btn_remove", variant="error", disabled=True)
            yield Rule()
            yield Label("Add filter", classes="hfm_section")
            with Horizontal(id="hfm_type_row"):
                yield Label("Type:")
                yield type_select
            yield Vertical(id="hfm_pairs_container")
            with Horizontal(id="hfm_add_ctrl"):
                yield Button("+ Add condition", id="hfm_btn_add_pair")
                yield Label("", id="hfm_add_ctrl_spacer")
                yield Button("Add Filter", id="hfm_btn_add_filter", variant="primary")
            yield Label("", id="hfm_status", markup=True)

    def on_mount(self):
        table = self.query_one("#hfm_filters_table", DataTable)
        table.add_column("On", key="on")
        table.add_column("ID", key="fid")
        table.add_column("Type", key="type")
        table.add_column("Rule", key="rule")
        self._rebuild_table()
        self._add_pair()

    def _rebuild_table(self):
        table = self.query_one("#hfm_filters_table", DataTable)
        table.clear()
        for f in self._fm.export():
            enabled = f.get("enabled", True)
            on_cell = Text("✓", style="bold green") if enabled else Text("○", style="dim")
            rule_str = " ".join(f"{k}={v}" for k, v in f["rule"].items())
            table.add_row(on_cell, str(f["id"]), f["type"], rule_str, key=str(f["id"]))
        self._selected_filter_id = None
        self.query_one("#hfm_btn_remove", Button).disabled = True

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted):
        if event.data_table.id != "hfm_filters_table":
            return
        if event.row_key and event.row_key.value is not None:
            self._selected_filter_id = int(event.row_key.value)
        self.query_one("#hfm_btn_remove", Button).disabled = self._selected_filter_id is None

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        if event.data_table.id != "hfm_filters_table":
            return
        if event.row_key and event.row_key.value is not None:
            self._selected_filter_id = int(event.row_key.value)
        table = self.query_one("#hfm_filters_table", DataTable)
        if table.hover_coordinate.column == 0:
            self._toggle_selected()

    def _toggle_selected(self):
        if self._selected_filter_id is None:
            return
        msg = self._fm.toggle(str(self._selected_filter_id))
        self._rebuild_table()
        self._on_filters_changed()
        self._set_status(msg)

    def _remove_selected(self):
        if self._selected_filter_id is None:
            return
        self._fm.remove(str(self._selected_filter_id))
        self._rebuild_table()
        self._on_filters_changed()
        self._set_status("")

    def _add_pair(self):
        self._pair_counter += 1
        pid = self._pair_counter
        self._active_pairs.append(pid)
        key_options = [(k, k) for k in self.VALID_KEYS]
        key_select = Select(
            key_options,
            id=f"hfm_pk_{pid}",
            value=self.VALID_KEYS[0],
            allow_blank=False,
            classes="hfm_pair_sel",
        )
        self._fit_select_width(key_select, key_options)
        row = Horizontal(
            Label("Condition:", classes="hfm_pair_label"),
            key_select,
            Input(id=f"hfm_pv_{pid}", placeholder="value  (* wildcards)"),
            Button("✕", id=f"hfm_prm_{pid}", classes="hfm_pair_rm"),
            id=f"hfm_pair_{pid}",
            classes="hfm_pair_row",
        )
        self.query_one("#hfm_pairs_container").mount(row)
        self._update_remove_buttons()

    def _remove_pair(self, pid: int):
        if len(self._active_pairs) <= 1:
            return
        self._active_pairs.remove(pid)
        try:
            self.query_one(f"#hfm_pair_{pid}").remove()
        except Exception:
            pass
        self._update_remove_buttons()

    def _update_remove_buttons(self):
        only_one = len(self._active_pairs) <= 1
        for pid in self._active_pairs:
            try:
                self.query_one(f"#hfm_prm_{pid}", Button).disabled = only_one
            except Exception:
                pass

    def _collect_pairs(self) -> list[str]:
        parts = []
        for pid in self._active_pairs:
            try:
                key = self.query_one(f"#hfm_pk_{pid}", Select).value
                val = self.query_one(f"#hfm_pv_{pid}", Input).value.strip()
                if val and not is_select_empty(key):
                    parts.append(f"{key}={val}")
            except Exception:
                pass
        return parts

    def _reset_pairs(self):
        for pid in list(self._active_pairs[1:]):
            self._remove_pair(pid)
        if self._active_pairs:
            try:
                self.query_one(f"#hfm_pv_{self._active_pairs[0]}", Input).value = ""
            except Exception:
                pass

    def _add_filter(self):
        f_type = self.query_one("#hfm_sel_type", Select).value
        if is_select_empty(f_type):
            return
        parts = self._collect_pairs()
        if not parts:
            self._set_status("[red]Enter at least one condition.[/red]")
            return
        msg = self._fm.add(str(f_type), parts)
        self._set_status(msg)
        self._reset_pairs()
        self._rebuild_table()
        self._on_filters_changed()

    def _set_status(self, msg: str):
        self.query_one("#hfm_status", Label).update(msg)

    def on_button_pressed(self, event: Button.Pressed):
        event.stop()
        button_id = event.button.id or ""
        if button_id == "hfm_btn_close":
            self.dismiss()
        elif button_id == "hfm_btn_remove":
            self._remove_selected()
        elif button_id == "hfm_btn_add_pair":
            self._add_pair()
        elif button_id == "hfm_btn_add_filter":
            self._add_filter()
        elif button_id.startswith("hfm_prm_"):
            self._remove_pair(int(button_id.split("_")[-1]))

    def on_input_submitted(self, event: Input.Submitted):
        if event.input.id and event.input.id.startswith("hfm_pv_"):
            self._add_filter()
