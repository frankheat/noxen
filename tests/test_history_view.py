import asyncio
import copy
from types import SimpleNamespace

from textual.widgets import Input, RichLog

from noxen.app import NoxenApp
from noxen.frida_session import ModificationResume
from noxen.history_table import HistoryTable
from tests.ui_test_case import IsolatedAppTestCase


def payload(i):
    return {'className': 'Example', 'methodName': 'getIntent', 'stackTrace': [],
            'infoIntent': {'action': f'EVENT_{i}', 'data': None, 'mimeType': None,
                           'extras': {}, 'flags': 0, 'categories': []}}


class HistoryViewTests(IsolatedAppTestCase):
    def make_app(self, count=20):
        app = NoxenApp(SimpleNamespace(project=None,
            new_project=str(self.settings_path.parent / 'view.noxen'), skip_device_scan=True))
        self.addCleanup(app.db.close)
        for i in range(count):
            app._on_history_intent(payload(i), i)
        return app

    async def open_history(self, app, pilot):
        app.query_one('#main_tabs').active = 'tab_history'
        await pilot.pause()
        return app.query_one(HistoryTable)

    def assert_detail(self, app, table):
        self.assertEqual(app._history_selected_entry['id'], table.selected_id)
        self.assertIn(app._history_selected_entry['intent']['action'],
                      '\n'.join(line.text for line in app.query_one('#history_detail', RichLog).lines))

    async def test_sort_header_clicks_and_hidden_id_keep_the_same_selected_event(self):
        app = self.make_app()
        async with app.run_test(size=(120, 45)) as pilot:
            table = await self.open_history(app, pilot)
            table.move_cursor(row=6)
            await pilot.pause()
            selected = table.selected_id
            await pilot.click('#history_table', offset=(2, 1))
            self.assertEqual(app._sort_column, 'id')
            self.assertFalse(app._sort_reverse)
            self.assertEqual(table.entry_at(0)['id'], 1)
            self.assertEqual(table.selected_id, selected)
            self.assert_detail(app, table)
            app._on_columns_changed({'action'})
            await pilot.pause()
            self.assertEqual(table.selected_id, selected)
            self.assert_detail(app, table)
            await pilot.click('#history_table', offset=(3, 1))
            self.assertEqual(app._sort_column, 'action')
            self.assertIn('↑', table.columns['action'].label)
            self.assert_detail(app, table)

    async def test_queued_highlights_cannot_replace_new_selection_or_cleared_results(self):
        app = self.make_app()
        async with app.run_test(size=(120, 45)) as pilot:
            table = await self.open_history(app, pilot)
            stale = HistoryTable.RowHighlighted(table, table.selected_id)
            table.move_cursor(row=7)
            app.on_history_table_row_highlighted(stale)
            await pilot.pause()
            self.assert_detail(app, table)
            app.query_one('#history_search', Input).value = 'not present'
            await pilot.pause()
            app.on_history_table_row_highlighted(stale)
            self.assertEqual(table.row_count, 0)
            self.assertIsNone(app._history_selected_entry)
            self.assertEqual(len(app.query_one('#history_detail', RichLog).lines), 0)
            app.query_one('#history_search', Input).value = ''
            await pilot.pause()
            self.assert_detail(app, table)

    async def test_filter_and_search_combination_and_escape_focus(self):
        app = self.make_app()
        async with app.run_test(size=(120, 45)) as pilot:
            table = await self.open_history(app, pilot)
            app._history_filter_manager.add('focus', ['action=EVENT_1*'])
            app._on_history_filters_changed()
            field = app.query_one('#history_search', Input)
            field.value = 'EVENT_19'
            await pilot.pause()
            self.assertEqual(table.row_count, 1)
            self.assertEqual(table.entry_at(0)['intent']['action'], 'EVENT_19')
            self.assert_detail(app, table)
            field.focus()
            await pilot.press('escape')
            self.assertEqual(field.value, '')
            self.assertIs(app.focused, table)
            self.assertEqual(table.row_count, 11)
            self.assert_detail(app, table)

    async def test_result_replacement_updates_detail_before_the_next_frame(self):
        app = self.make_app()
        async with app.run_test(size=(120, 45)) as pilot:
            table = await self.open_history(app, pilot)
            app._history_search_text = 'EVENT_7'
            app._refresh_rows_only()
            self.assertEqual(table.row_count, 1)
            self.assert_detail(app, table)
            app._history_search_text = 'no results'
            app._refresh_rows_only()
            self.assertIsNone(app._history_selected_entry)
            self.assertIsNone(table.selected_id)
            self.assertEqual(len(app.query_one('#history_detail', RichLog).lines), 0)

    async def test_offscreen_modification_updates_search_width_and_detail(self):
        app = self.make_app(60)
        async with app.run_test(size=(120, 45)) as pilot:
            table = await self.open_history(app, pilot)
            original = app._all_intents[0]
            modified = copy.deepcopy(original['intent'])
            modified['action'] = 'MODIFIED_OFFSCREEN_' + 'x' * 100
            await asyncio.to_thread(app._finalize_forward, original['id'], original,
                                    [('action', '', modified['action'], '')],
                                    ModificationResume(True, {'ok': True, 'infoIntent': modified}))
            await pilot.pause(.2)
            self.assertEqual(table.columns['action'].content_width, len(modified['action']))
            app.query_one('#history_search', Input).value = 'MODIFIED_OFFSCREEN'
            await pilot.pause()
            self.assertEqual(table.row_count, 1)
            self.assertEqual(table.selected_id, original['id'])
            self.assert_detail(app, table)
            self.assertIn('MODIFIED', '\n'.join(line.text for line in app.query_one('#history_detail', RichLog).lines))
            stored = app.db._load_all()[0]
            self.assertEqual(stored['intent']['action'], modified['action'])
            self.assertEqual(stored['outcome'], 'modified_forwarded')

    async def test_clear_then_capture_rejects_old_selection_and_preserves_saved_preferences(self):
        app = self.make_app()
        async with app.run_test(size=(120, 45)) as pilot:
            table = await self.open_history(app, pilot)
            stale = HistoryTable.RowHighlighted(table, table.selected_id)
            app._on_columns_changed({'id', 'action'})
            app._on_history_column_widths_changed({'action': 17})
            await pilot.pause()
            app.action_clear_history()
            app._on_history_intent(payload(99), 99)
            app._do_history_refresh()
            app.on_history_table_row_highlighted(stale)
            await pilot.pause()
            self.assertEqual(table.row_count, 1)
            self.assertEqual(table.columns['action'].width, 17)
            self.assert_detail(app, table)
            self.assertEqual(app._history_selected_entry['intent']['action'], 'EVENT_99')
            self.assertEqual(set(app.db.load_history_columns()), {'id', 'action'})
            self.assertEqual(app.db.load_history_column_widths(), {'action': 17})
            self.assertEqual(len(app.db._load_all()), 1)

    async def test_resize_panel_theme_and_command_bar_preserve_selection_and_clicks(self):
        app = self.make_app(60)
        async with app.run_test(size=(120, 45)) as pilot:
            table = await self.open_history(app, pilot)
            table.move_cursor(row=30)
            await pilot.pause()
            selected = table.selected_id
            for theme in ('noxen-light', 'noxen-dark'):
                app.theme = theme
                app._refresh_theme_content()
                app._adjust_history_split(2)
                app._toggle_history_command_bar()
                await pilot.resize_terminal(100, 35)
                await pilot.pause()
                self.assertEqual(table.selected_id, selected)
                self.assert_detail(app, table)
                await pilot.click('#history_table', offset=(3, 3))
                self.assert_detail(app, table)
                selected = table.selected_id
