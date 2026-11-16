import asyncio
import copy
import unittest
from unittest.mock import Mock, patch

from textual.app import App
from textual.widgets import Button, Input, Select, TextArea

from noxen.sender import validate_request, OPERATIONS, INTENT_OPERATIONS
from noxen.sender_editor import (MISSING, OptionalSection, ScalarField, ValueEditor,
                                 SenderTextModal, escaped_text, unescape_text, TYPES, default_value)
from noxen.sender_ui import SenderRequestModal


class TextTests(unittest.TestCase):
    def test_special_text_roundtrip_without_json_syntax(self):
        for value in ('', '"quotes"', r'\n', 'a\r\nb\rc\nd\x00\t\u202e', '😀'):
            self.assertEqual(unescape_text(escaped_text(value)), value)
        for value in ('\\', r'\q', r'\u12', r'\ud800'):
            with self.assertRaises(ValueError):
                unescape_text(value)


class EditorTests(unittest.IsolatedAsyncioTestCase):
    async def test_existing_nested_request_roundtrips_all_supported_types(self):
        extras = {kind: {'type': kind, 'value': default_value(kind)} for kind in TYPES}
        extras.update({
            'long': {'type': 'long', 'value': '9223372036854775807'},
            'char': {'type': 'char', 'value': 'x'},
            'special': {'type': 'String', 'value': 'a\r\nb\rc\nd\x00'},
            'null': {'type': 'String', 'value': None},
            'bundle': {'type': 'Bundle', 'value': {'next': {'type': 'Intent', 'value': {'action': 'nested'}}}},
            'nullBundle': {'type': 'Bundle', 'value': None},
            'nullArray': {'type': 'String[]', 'value': None},
            'array': {'type': 'Intent[]', 'value': [None, {'action': ''}]},
        })
        request = validate_request({'operation': 'sendBroadcast', 'receiverPermission': '', 'intent': {
            'component': None, 'action': '', 'data': 'test', 'flags': 1, 'categories': ['a', ''],
            'extras': extras, 'selector': {'action': 'select'}, 'clipData': {
                'label': '', 'mimeTypes': ['text/plain'], 'items': [
                    {'text': 'one', 'uri': None}, {'intent': {'extras': {'x': {'type': 'String', 'value': ''}}}}]}}})
        original = copy.deepcopy(request)
        app = App()
        async with app.run_test(size=(120, 40)) as pilot:
            modal = SenderRequestModal(Mock(), {'request': request, 'name': 'nested', 'id': 1, 'revision': 1})
            app.push_screen(modal)
            await pilot.pause()
            self.assertEqual(modal.collect_request(), original)
            self.assertEqual(request, original)
            self.assertFalse(modal.query(TextArea))

    async def test_add_edit_remove_and_switch_type_preserves_drafts(self):
        app = App()
        async with app.run_test(size=(100, 40)) as pilot:
            modal = SenderRequestModal(Mock())
            app.push_screen(modal)
            await pilot.pause()
            extras = next(f for f in modal.fields if f.key == 'extras')
            extras.query_one('.section_toggle', Button).press()
            await pilot.pause()
            row = extras.editor.members[0]
            row.key_field.query_one(Input).value = 'payload'
            row.editor.members[0].query_one(Input).value = 'hello'
            row.query_one('.entry_header > Select', Select).value = 'Bundle'
            await pilot.pause()
            row.editor.query_one('.add_entry', Button).press()
            await pilot.pause()
            child = row.editor.members[0]
            child.key_field.query_one(Input).value = 'nested'
            child.editor.members[0].query_one(Input).value = 'value'
            self.assertEqual(modal.collect_request()['intent']['extras']['payload']['value'],
                             {'nested': {'type': 'String', 'value': 'value'}})
            row.query_one('.entry_header > Select', Select).value = 'String'
            await pilot.pause()
            self.assertEqual(row.collect(), 'hello')
            row.query_one('.entry_header > Select', Select).value = 'Bundle'
            await pilot.pause()
            self.assertIn('nested', row.collect())
            row.query_one('.remove_entry', Button).press()
            await pilot.pause()
            self.assertEqual(extras.collect(), {})
            extras.query_one('.section_toggle', Button).press()
            await pilot.pause()
            self.assertNotIn('extras', modal.collect_request()['intent'])

    async def test_explorer_keeps_nested_draft_and_hides_unrelated_fields(self):
        app = App()
        async with app.run_test(size=(120, 40)) as pilot:
            request = {'operation': 'sendBroadcast', 'intent': {'action': 'root', 'extras': {
                'destination': {'type': 'Intent', 'value': {'action': 'child'}}}}}
            modal = SenderRequestModal(Mock(), {'request': request, 'name': 'tree', 'id': 1, 'revision': 1})
            app.push_screen(modal)
            await pilot.pause()
            extras = next(f for f in modal.fields if f.key == 'extras')
            self.assertFalse(extras.display)
            modal.focus_request_object(extras)
            self.assertTrue(extras.display)
            self.assertFalse(modal.query_one('#sender_field_action').display)
            row = extras.editor.members[0]
            row.query_one('.open_value', Button).press()
            await pilot.pause()
            self.assertIs(modal._object_target, row.editor)
            # The open object shows none of the headings or buttons of the levels above it.
            self.assertFalse(extras.query_one('.section_header').display)
            self.assertFalse(extras.editor.query_one('.column_headings').display)
            self.assertFalse(row.query_one('.entry_header').display)
            self.assertTrue(row.query_one('.set_null').display)
            self.assertFalse(modal.query_one('#sender_request_tree').auto_expand)
            action = next(f for f in row.editor.members if f.key == 'action')
            self.assertTrue(action.display)
            action.query_one(Input).value = 'edited child'
            modal.focus_request_object(None)
            self.assertTrue(modal.query_one('#sender_field_action').display)
            result = modal.collect_request()
            self.assertEqual(result['intent']['action'], 'root')
            self.assertEqual(result['intent']['extras']['destination']['value']['action'], 'edited child')
            await pilot.resize_terminal(60, 24)
            await pilot.pause()
            self.assertTrue(modal.has_class('narrow_request'))

    async def test_create_categories_selector_and_clipdata_without_json(self):
        app = App()
        async with app.run_test(size=(100, 45)) as pilot:
            modal = SenderRequestModal(Mock())
            app.push_screen(modal)
            await pilot.pause()
            sections = {f.key: f for f in modal.fields if isinstance(f, OptionalSection)}
            categories = sections['categories']
            categories.query_one('.section_toggle', Button).press()
            await pilot.pause()
            self.assertEqual(len(categories.editor.members), 1)
            categories.editor.members[0].editor.members[0].query_one(Input).value = 'first'
            categories.query_one('.section_add_entry', Button).press()
            await pilot.pause()
            categories.editor.members[1].editor.members[0].query_one(Input).value = 'second'
            categories.editor.members[0].query_one('.remove_entry', Button).press()
            await pilot.pause()
            self.assertEqual(categories.collect(), ['second'])
            self.assertEqual(categories.editor.members[0].key, 0)
            selector = sections['selector']
            selector.query_one('.section_toggle', Button).press()
            await pilot.pause()
            next(f for f in selector.editor.members if f.key == 'action').query_one(Input).value = 'selected'
            clip = sections['clipData']
            clip.query_one('.section_toggle', Button).press()
            await pilot.pause()
            fields = {f.key: f for f in clip.editor.members}
            fields['mimeTypes'].query_one('.section_toggle', Button).press()
            fields['items'].query_one('.section_toggle', Button).press()
            await pilot.pause()
            fields['mimeTypes'].editor.members[0].editor.members[0].query_one(Input).value = 'text/plain'
            item = fields['items'].editor.members[0].editor
            next(f for f in item.members if f.key == 'text').query_one(Input).value = 'clip text'
            request = validate_request(modal.collect_request())
            self.assertEqual(request['intent']['selector'], {'action': 'selected'})
            self.assertEqual(request['intent']['clipData'], {'mimeTypes': ['text/plain'], 'items': [{'text': 'clip text'}]})

    async def test_provider_fields_and_operation_switch_preserve_values(self):
        app = App()
        async with app.run_test(size=(90, 35)) as pilot:
            for operation in OPERATIONS:
                if operation in INTENT_OPERATIONS:
                    request = {'operation': operation, 'intent': {'flags': 0x10000000}}
                else:
                    request = {'operation': operation, 'uri': 'content://example/path'}
                    if operation in ('insert', 'update'):
                        request['values'] = {'blob': {'type': 'byte[]', 'value': [-1, 0, 127]}}
                    if operation == 'query':
                        request.update(projection=[], selection=None, selectionArgs=['', 'x\x00'])
                    if operation == 'call':
                        request.update(method='', arg='', extras=None)
                request = validate_request(request)
                modal = SenderRequestModal(Mock(), {'request': request, 'name': 'request', 'id': 1, 'revision': 1})
                app.push_screen(modal)
                await pilot.pause()
                self.assertEqual(modal.collect_request(), request)
                original_op = operation
                other = 'getType' if operation != 'getType' else 'query'
                modal.query_one('#sender_operation', Select).value = other
                await pilot.pause()
                modal.query_one('#sender_operation', Select).value = original_op
                await pilot.pause()
                self.assertEqual(modal.collect_request(), request)
                modal.dismiss(None)
                await pilot.pause()

    async def test_save_cannot_collect_half_mounted_entry(self):
        app = App()
        async with app.run_test() as pilot:
            editor = ValueEditor('Bundle', {})
            await app.screen.mount(editor)
            await pilot.pause()
            entries = editor.query_one('.entries')
            original_mount = entries.mount
            started, resume = asyncio.Event(), asyncio.Event()

            async def delayed_mount(*widgets):
                started.set()
                await resume.wait()
                await original_mount(*widgets)

            with patch.object(entries, 'mount', side_effect=delayed_mount):
                task = asyncio.create_task(editor.add_entry())
                try:
                    await asyncio.wait_for(started.wait(), 2)
                    with self.assertRaisesRegex(ValueError, 'updating'):
                        editor.collect()
                finally:
                    resume.set()
                    await task
            self.assertEqual(editor.collect(), {'': {'type': 'String', 'value': ''}})

    async def test_duplicate_keys_and_invalid_numeric_values_do_not_save(self):
        app = App()
        async with app.run_test() as pilot:
            editor = ValueEditor('Bundle', {'a': {'type': 'int', 'value': 1}, 'b': {'type': 'String', 'value': ''}})
            await app.screen.mount(editor)
            await pilot.pause()
            editor.members[1].key_field.query_one(Input).value = 'a'
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                editor.collect()
            editor.members[1].key_field.query_one(Input).value = 'b'
            editor.members[0].editor.members[0].query_one(Input).value = 'not a number'
            with self.assertRaisesRegex(ValueError, 'valid int'):
                editor.collect()

    async def test_text_cancel_and_explicit_empty_null_absent(self):
        app = App()
        async with app.run_test(size=(60, 24)) as pilot:
            field = ScalarField('action', 'String', MISSING, optional=True, nullable=True)
            await app.screen.mount(field)
            await pilot.pause()
            self.assertIs(field.collect(), MISSING)
            field.query_one(Button).press()
            await pilot.pause()
            self.assertIsInstance(app.screen, SenderTextModal)
            app.screen.query_one(Select).value = 'text'
            app.screen.query_one(TextArea).load_text('discarded')
            await pilot.click('#sender_text_cancel')
            await pilot.pause()
            self.assertIs(field.collect(), MISSING)
            for mode, expected in [('text', ''), ('null', None), ('absent', MISSING)]:
                field.query_one(Button).press()
                await pilot.pause()
                app.screen.query_one(Select).value = mode
                app.screen.query_one(TextArea).load_text('')
                await pilot.click('#sender_text_apply')
                await pilot.pause()
                self.assertEqual(field.collect(), expected)
