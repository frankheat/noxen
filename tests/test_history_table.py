import unittest
from unittest.mock import patch

from rich.text import Text
from rich.style import Style
from rich.color import Color
from textual import events
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import DataTable

from noxen.history_table import HistoryTable
from noxen.rendering import history_row_values, history_sort_key
from noxen.ui_theme import register_noxen_themes, semantic_colors


COLUMNS = [("id", "# ↓"), ("outcome", "→/✗"), ("time", "Time"), ("method", "Method"),
           ("class", "Class"), ("component", "Component"), ("action", "Action"), ("extras", "Extras")]


def entry(number, **changes):
    result = {"id": number, "timestamp": "2026-10-18T08:00:00.123", "method": "getIntent",
              "class": "Example", "outcome": "forwarded",
              "intent": {"component": "example/.Target", "action": f"ACTION_{number}", "extras": {}}}
    result.update(changes)
    return result


class TableApp(App):
    CSS = 'DataTable, HistoryTable { width: 1fr; height: 1fr; }'

    def __init__(self, items):
        super().__init__()
        self.items = items
        self.highlights = []
        self.headers = []
        register_noxen_themes(self)
        self.theme = "noxen-dark"

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield DataTable(id="reference", cursor_type="row")
            yield HistoryTable(id="candidate")

    def on_mount(self):
        reference = self.query_one(DataTable)
        for key, title in COLUMNS:
            reference.add_column(title, key=key)
        for item in self.items:
            cells = history_row_values(item, {key for key, _ in COLUMNS}, COLUMNS)
            # Reference uses literal payload values too: markup is not Intent data.
            reference.add_row(*(c if isinstance(c, Text) else Text(c) for c in cells), key=str(item["id"]))
        candidate = self.query_one(HistoryTable)
        candidate.configure_columns([(key, title, None) for key, title in COLUMNS])
        candidate.set_entries(self.items)

    def on_history_table_row_highlighted(self, event):
        self.highlights.append(event.entry_id)

    def on_history_table_header_selected(self, event):
        self.headers.append(event.column_key)


class HistoryTableTests(unittest.IsolatedAsyncioTestCase):
    async def test_auto_widths_and_visible_text_match_literal_native_table(self):
        items = [entry(i) for i in range(40)]
        items[-1]["class"] = "VeryLongOffscreenComponent" * 3
        items[2]["intent"]["action"] = "🧪 漢字 e\u0301 [bold]literal[/bold]\nnot on this row"
        items[3]["intent"]["action"] = "\x1b\x00\r"
        items[4]["modification_error"] = "warning"
        app = TableApp(items)
        async with app.run_test(size=(180, 24)) as pilot:
            await pilot.pause()
            ref, table = app.query_one(DataTable), app.query_one(HistoryTable)
            self.assertEqual([c.content_width for c in ref.columns.values()],
                             [c.content_width for c in table.columns.values()])
            for y in range(10):
                self.assertEqual(ref.render_line(y).text, table.render_line(y).text)
            before = table.virtual_size.width
            table.scroll_to(y=25, animate=False)
            await pilot.pause()
            self.assertEqual(table.virtual_size.width, before)

    async def test_arrivals_preserve_visible_anchor_when_selection_is_offscreen(self):
        items = [entry(i) for i in range(100)]
        app = TableApp(items)
        async with app.run_test(size=(120, 24)) as pilot:
            table = app.query_one(HistoryTable)
            await pilot.pause()
            table.scroll_to(y=35, animate=False)
            await pilot.pause()
            top = table.entry_at(int(table.scroll_y))['id']
            selected = table.selected_id
            table.set_entries([entry(-1), entry(-2)] + items)
            await pilot.pause()
            self.assertEqual(table.entry_at(int(table.scroll_y))['id'], top)
            self.assertEqual(table.selected_id, selected)

    async def test_tabs_markup_and_control_characters_are_literal_single_line_data(self):
        item = entry(1)
        item['intent']['action'] = 'a\tb[bold]literal[/bold]\nsecond line'
        app = TableApp([item])
        async with app.run_test(size=(180, 24)) as pilot:
            table = app.query_one(HistoryTable)
            table.configure_columns([('action', 'Action', None)])
            table.set_entries([item])
            await pilot.pause()
            line = table.render_line(1).text
            self.assertIn('a       b[bold]literal[/bold]', line)
            self.assertNotIn('second line', line)
            self.assertEqual(table.columns['action'].content_width, 29)

    async def test_native_keyboard_navigation_and_horizontal_scroll(self):
        app = TableApp([entry(i) for i in range(100)])
        async with app.run_test(size=(100, 24)) as pilot:
            await pilot.pause()
            ref, table = app.query_one(DataTable), app.query_one(HistoryTable)
            for key in ('down', 'down', 'pagedown', 'pagedown', 'pageup', 'ctrl+end', 'up',
                        'ctrl+home', 'end', 'home', 'right', 'left'):
                ref.focus()
                await pilot.press(key)
                ref_row, ref_y, ref_x = ref.cursor_row, ref.scroll_y, ref.scroll_x
                table.focus()
                await pilot.press(key)
                self.assertEqual(table.cursor_row, ref_row, key)
                self.assertEqual(table.scroll_y, ref_y, key)
                self.assertEqual(table.scroll_x, ref_x, key)

    async def test_fixed_width_and_horizontal_cropping_match_native_with_wide_unicode(self):
        item = entry(1)
        item['intent']['action'] = 'A漢🧪e\u0301Ｂ[bold]literal[/bold]' * 3
        app = TableApp([item])
        async with app.run_test(size=(48, 12)) as pilot:
            ref, table = app.query_one(DataTable), app.query_one(HistoryTable)
            for width in (7, 40):
                ref.clear(columns=True)
                ref.add_column('Action', key='action', width=width)
                ref.add_row(Text(item['intent']['action']), key='1')
                table.configure_columns([('action', 'Action', width)])
                table.set_entries([item])
                await pilot.pause()
                for offset in (0, 1, 3, 9, 17):
                    ref.scroll_to(x=offset, animate=False)
                    table.scroll_to(x=offset, animate=False)
                    await pilot.pause()
                    self.assertEqual(ref.render_line(1).text, table.render_line(1).text, (width, offset))

    async def test_selection_scroll_and_empty_results(self):
        items = [entry(i) for i in range(100)]
        app = TableApp(items)
        async with app.run_test(size=(120, 24)) as pilot:
            table = app.query_one(HistoryTable)
            await pilot.pause()
            table.move_cursor(row=55)
            await pilot.pause()
            offset = table.cursor_row - table.scroll_y
            table.set_entries([entry(-1), entry(-2)] + items)
            await pilot.pause()
            self.assertEqual(table.selected_id, 55)
            self.assertEqual(table.cursor_row - table.scroll_y, offset)
            table.set_entries(list(reversed(items)))
            await pilot.pause()
            self.assertEqual(table.selected_id, 55)
            self.assertEqual(table.entry_at(table.cursor_row)["id"], 55)
            table.set_entries([items[55]])
            await pilot.pause()
            self.assertEqual(table.selected_id, 55)
            self.assertEqual(table.scroll_y, 0)
            table.clear()
            await pilot.pause()
            self.assertIsNone(table.selected_id)
            self.assertIsNone(app.highlights[-1])
            await pilot.press('down', 'pagedown', 'ctrl+end')
            table.set_entries(items)
            await pilot.pause()
            self.assertEqual(table.selected_id, 0)

    async def test_hidden_columns_negative_ids_ties_and_both_directions(self):
        items = [entry(i if i % 2 else -i - 1, method='same', **{'class': 'A' if i % 3 else 'a'})
                 for i in range(24)]
        app = TableApp(items)
        async with app.run_test() as pilot:
            table = app.query_one(HistoryTable)
            for columns in (COLUMNS, [('method', 'Method')], [('outcome', '→/✗')], [('extras', 'Extras')]):
                table.configure_columns([(key, label, None) for key, label in columns])
                for key, _ in COLUMNS:
                    for reverse in (False, True):
                        expected = sorted(items, key=lambda e: history_sort_key(e, key), reverse=reverse)
                        table.set_entries(expected)
                        self.assertEqual([table.entry_at(i)['id'] for i in range(table.row_count)],
                                         [e['id'] for e in expected])
            await pilot.pause()

    async def test_modified_events_widths_and_theme_have_no_stale_render_cache(self):
        items = [entry(1), entry(2)]
        app = TableApp(items)
        async with app.run_test(size=(140, 24)) as pilot:
            table = app.query_one(HistoryTable)
            table.configure_columns([('action', 'Action', None), ('outcome', '→/✗', None)])
            table.set_entries(items)
            await pilot.pause()
            items[1]['intent']['action'] = 'W' * 120
            items[1]['outcome'] = 'modified_forwarded'
            items[1]['modification_error'] = 'failed'
            table.set_entries(items)
            await pilot.pause()
            self.assertEqual(table.columns['action'].content_width, 120)
            table.action_horizontal_end()
            await pilot.pause()
            self.assertIn('✎→ !', table.render_line(2).text)
            items[1]['intent']['action'] = 'short'
            table.set_entries(items)
            await pilot.pause()
            self.assertLess(table.columns['action'].content_width, 120)
            dark = list(table.render_line(1))
            app.theme = 'noxen-light'
            await pilot.pause()
            self.assertNotEqual(dark, list(table.render_line(1)))
            table.configure_columns([('action', 'Action ↑', 7)])
            table.set_entries(items)
            await pilot.pause()
            self.assertEqual(table.columns['action'].render_width, 9)
            table.configure_columns([])
            table.set_entries(items)
            await pilot.pause()
            self.assertIsNone(table.selected_id)

    async def test_mouse_header_and_row_selection_after_horizontal_scroll(self):
        app = TableApp([entry(i) for i in range(50)])
        async with app.run_test(size=(180, 24)) as pilot:
            table = app.query_one(HistoryTable)
            await pilot.pause()
            await pilot.click('#candidate', offset=(2, 0))
            self.assertEqual(app.headers[-1], 'id')
            await pilot.click('#candidate', offset=(3, 4))
            self.assertEqual(table.selected_id, 3)
            table.scroll_to(x=30, y=20, animate=False)
            await pilot.pause()
            await pilot.click('#candidate', offset=(3, 4))
            self.assertEqual(table.selected_id, 23)
            await pilot.resize_terminal(100, 15)
            await pilot.pause()
            self.assertEqual(table.selected_id, 23)

    async def test_only_visible_rows_are_formatted_even_with_10000_results(self):
        app = TableApp([])
        async with app.run_test(size=(120, 24)) as pilot:
            table = app.query_one(HistoryTable)
            with patch('noxen.history_table.history_row_values', wraps=history_row_values) as formatter:
                table.set_entries([entry(i) for i in range(10000)])
                await pilot.pause()
                self.assertEqual(table.row_count, 10000)
                self.assertLess(formatter.call_count, 100)
            table.action_last()
            await pilot.pause()
            self.assertEqual(table.selected_id, 9999)
            self.assertIn('9999', '\n'.join(table.render_line(y).text for y in range(table.size.height)))

    async def test_focused_selection_style_matches_native_in_both_themes(self):
        app = TableApp([entry(1), entry(2), entry(3, outcome='dropped')])
        async with app.run_test() as pilot:
            ref, table = app.query_one(DataTable), app.query_one(HistoryTable)
            for theme in ('noxen-dark', 'noxen-light'):
                app.theme = theme
                ref.focus()
                await pilot.pause()
                native_style = ref.get_component_rich_style('datatable--cursor')
                table.focus()
                await pilot.pause()
                candidate_style = table.get_component_rich_style('history-table--cursor')
                self.assertEqual((candidate_style.color, candidate_style.bgcolor, candidate_style.bold),
                                 (native_style.color, native_style.bgcolor, native_style.bold))
                colors = semantic_colors(app.current_theme.dark)
                for row, glyph, expected in ((2, '→', colors.success), (3, '✗', colors.error)):
                    styles = [s.style for s in table.render_line(row) if glyph in s.text]
                    self.assertTrue(styles)
                    self.assertEqual(styles[0].color, Color.parse(expected))

    async def test_mouse_wheel_hover_and_extremely_wide_offscreen_columns(self):
        items = [entry(i) for i in range(100)]
        items[-1]['class'] = 'X' * 200000
        app = TableApp(items)
        async with app.run_test(size=(120, 24)) as pilot:
            table = app.query_one(HistoryTable)
            await pilot.pause()
            await pilot.hover('#candidate', offset=(2, 0))
            self.assertEqual(table._hover_header, 'id')
            same_header = events.MouseMove(table, 2, 0, 1, 0, 0, False, False, False,
                style=Style(meta={'history_header': True, 'history_column': 'id'}))
            with patch.object(table, 'refresh') as redraw:
                table.on_mouse_move(same_header)
                redraw.assert_not_called()
            selected = table.selected_id
            table.post_message(events.MouseScrollDown(table, 3, 4, 0, 1, 0, False, False, False))
            await pilot.pause()
            self.assertGreater(table.scroll_y, 0)
            self.assertEqual(table.selected_id, selected)
            before = table.virtual_size.width
            self.assertGreater(before, 200000)
            # Short values in a very wide column are padded only to the visible
            # slice. Fields wholly outside it need no Rich conversion.
            table.scroll_to(x=100000, animate=False)
            await pilot.pause()
            strip = table.render_line(1)
            self.assertEqual(strip.cell_length, table.size.width)
            self.assertLessEqual(sum(len(segment.text) for segment in strip), table.size.width)
            self.assertEqual(table.virtual_size.width, before)
