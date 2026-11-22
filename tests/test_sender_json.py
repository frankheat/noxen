import unittest

from textual.app import App

from noxen.sender import validate_request
from noxen.sender_json import (apply_completion, completions, expand, format_request, highlights, parse,
                               toggle_fold)
from noxen.sender_json_editor import JsonRequestEditor


def complete(marked, pick=None, always=False):
    """`|` marks the cursor. Returns the offered names, or the text after accepting `pick`."""
    offset = marked.index("|")
    text = marked.replace("|", "")
    found, matches = completions(text, offset, always)
    if pick is None:
        return [name for name, _ in matches]
    snippet = next(snippet for name, snippet in matches if name == pick)
    text, cursor, selected = apply_completion(text, offset, found, snippet)
    return text[:cursor] + "|" + text[cursor:]


class SenderJsonTests(unittest.TestCase):
    def test_free_keys_and_text_never_offer_types_or_literals(self):
        from noxen.sender import OPERATIONS

        def choices(marked, root="request"):
            offset = marked.index("|")
            _, matches = completions(marked.replace("|", ""), offset, True, root=root)
            return matches

        for operation in ("insert", "update"):
            for key in ('"|', '"tit|'):
                document = '{"operation": "' + operation + '", "values": {' + key + '": {"type": "String", "value": "demo"}}}'
                self.assertEqual(choices(document), [], document)
        for operation in OPERATIONS:
            document = '{"operation": "' + operation + '", "extras": {"|": {"type": "String", "value": ""}}}'
            self.assertEqual(choices(document), [], operation)
        for marked in (
            '{"intent":{"extras":{"|":{"type":"String","value":""}}}}',
            '{"operation":"query","selection":"tit|"}',
            '{"operation":"query","selectionArgs":["fir|"]}',
            '{"operation":"insert","values":{"title":{"type":"String","value":"te|"}}}',
            '{"operation":"call","method":"ec|"}',
            '{"operation":"query","uri":"content://de|"}',
        ):
            self.assertEqual(choices(marked), [], marked)
        self.assertEqual(choices('{"values":{"|":{"type":"String","value":""}}}', root="provider"), [])
        self.assertEqual(choices('{"value":"te|"}', root="providerResponse"), [])
        self.assertEqual(choices('{"rows":[[{"type":"string","value":"te|"}]]}', root="cursor"), [])
        self.assertEqual(choices('{"operation":"query","maxRows":|}'), [("maxRows", "100$0")])
        self.assertEqual(choices('{"operation":"query","projection":[|]}'), [])

    def test_provider_content_values_types_and_defaults_match_the_editor(self):
        def offered(marked, root="provider", operation="insert"):
            offset = marked.index("|")
            _, options = completions(marked.replace("|", ""), offset, True, root=root, operation=operation)
            return options

        self.assertEqual([name for name, _ in offered('{"values": {|}}')],
                         ["String", "boolean", "int", "long"])
        self.assertEqual([name for name, _ in offered('{"values": {"x": {"type": "|"}}}')],
                         ["String", "boolean", "int", "long"])
        sender = '{"operation": "insert", "values": {"x": {"type": "|"}}}'
        names = [name for name, _ in offered(sender, root="request")]
        self.assertIn("double", names)
        self.assertIn("byte[]", names)
        self.assertNotIn("Intent", names)
        self.assertNotIn("Bundle", names)
        self.assertEqual(offered('{"values": {"x": {"type": "long", "value": |}}}'), [("long", '"0$0"')])
        self.assertEqual([name for name, _ in offered('{"values": {"x": {"type": "boolean", "value": |}}}')],
                         ["true", "false"])
        self.assertEqual([name for name, _ in offered('{"queryArguments": {|}}', operation="query")],
                         ["selection", "selectionArgs", "sortOrder"])
        self.assertEqual(offered('{"value": |}', root="providerResponse"), [("String", '"$0"'), ("null", "null$0")])
        self.assertEqual(offered('{"rows": [[{"type": "integer", "value": |}]]}', root="cursor"),
                         [("integer", '"0$0"')])

    def test_names_follow_the_object_under_the_cursor(self):
        self.assertEqual(complete('{"operation": "sendBroadcast", "intent": {fl|}}'), ["flags"])
        self.assertEqual(complete('{"operation": "st|"}')[:2], ["startActivity", "startService"])
        self.assertEqual(complete('{"operation": "query", |}', always=True),
                         ["uri", "projection", "selection", "selectionArgs", "sortOrder", "maxRows", "maxBytes"])
        self.assertNotIn("action", complete('{"operation": "sendBroadcast", "intent": {"action": "a", a|}}'))
        self.assertEqual(complete('{"operation": "call", "extras": {"k": {"type": "In|"}}}')[:2], ["Intent", "Intent[]"])
        # The value of a typed entry is known from the type written before it.
        self.assertIn("action", complete('{"operation": "call", "extras": {"k": {"type": "Intent", "value": {a|}}}}'))
        self.assertEqual(complete('{"operation": "call", "extras": {"k": {"type": "Bundle", "value": {St|}}}}'),
                         ["String", "String[]"])
        self.assertEqual(complete('{"operation": "sendBroadcast", "intent": {"clipData": {"items": [{te|}]}}}'),
                         ["text", "htmlText", "intent"])
        self.assertEqual(complete('{"operation": "sendBroadcast", "intent": {"action": "plain te|"}}'), [])
        self.assertEqual(complete('{"operation": "sendBroadcast", |}'), [])  # Nothing typed, nothing offered.

    def test_accepting_a_name_writes_its_structure(self):
        self.assertEqual(complete('{\n    "operation": "sendBroadcast",\n    in|\n}', "intent"),
                         '{\n    "operation": "sendBroadcast",\n    "intent": {\n        "component": |null,\n'
                         '        "action": null,\n        "data": null,\n        "flags": [],\n'
                         '        "categories": [],\n        "extras": {}\n    }\n}')
        # A missing comma after the previous member is added; a typed quote pair is consumed.
        self.assertEqual(complete('{\n    "intent": {\n        "action": "x"\n        "ca|"\n    }\n}', "categories"),
                         '{\n    "intent": {\n        "action": "x",\n        "categories": [|]\n    }\n}')
        self.assertEqual(complete('{"operation": "call", "extras": {\n    St|\n}}', "String"),
                         '{"operation": "call", "extras": {\n    "|": {"type": "String", "value": ""}\n}}')
        self.assertEqual(complete('{"operation": "st|"}', "startActivity"), '{"operation": "startActivity"|}')
        # In a new request, the operation brings what it needs; in one with other fields it does not.
        self.assertEqual(complete('{\n    "operation": "|"\n}', "sendBroadcast", always=True),
                         '{\n    "operation": "sendBroadcast",\n    "intent": {\n        |\n    }\n}')
        self.assertEqual(complete('{\n    "operation": "|"\n}', "query", always=True),
                         '{\n    "operation": "query",\n    "uri": "content://|"\n}')
        self.assertEqual(complete('{\n    "operation": "|",\n    "intent": {}\n}', "query", always=True),
                         '{\n    "operation": "query"|,\n    "intent": {}\n}')

    def test_snippets_produce_requests_that_validate(self):
        text = complete('{\n    "operation": "sendBroadcast",\n    in|\n}', "intent").replace("|", "")
        self.assertEqual(validate_request(parse(text))["intent"]["flags"], [])
        text = complete('{\n    "operation": "|"\n}', "startActivity", always=True).replace("|", "")
        self.assertEqual(validate_request(parse(text))["intent"]["flags"], ["FLAG_ACTIVITY_NEW_TASK"])

    def test_flag_choices_complete_inside_arrays_and_at_the_value(self):
        activity = '{"operation": "startActivity", "intent": {"flags": [|]}}'
        broadcast = activity.replace("startActivity", "sendBroadcast")
        self.assertTrue(complete(activity)[0].startswith("FLAG_ACTIVITY_"))
        self.assertTrue(complete(broadcast)[0].startswith("FLAG_RECEIVER_"))
        typed = activity.replace('[|]', '["new_t|"]')
        result = complete(typed, "FLAG_ACTIVITY_NEW_TASK").replace("|", "")
        self.assertEqual(validate_request(parse(result))["intent"]["flags"], ["FLAG_ACTIVITY_NEW_TASK"])
        self.assertNotIn("FLAG_ACTIVITY_NEW_TASK",
                         complete(activity.replace("[|]", '["FLAG_ACTIVITY_NEW_TASK", |]')))
        typed = activity.replace('[|]', '|')
        result = complete(typed, "FLAG_ACTIVITY_NEW_TASK", always=True).replace("|", "")
        self.assertEqual(validate_request(parse(result))["intent"]["flags"], ["FLAG_ACTIVITY_NEW_TASK"])
        nested = activity.replace('"flags": [|]', '"selector": {"flags": [|]}')
        self.assertTrue(complete(nested)[0].startswith("FLAG_GRANT_"))
        text = '{"flags": ["NEW_T"]}'
        _, options = completions(text, text.index('T"') + 1, root="intent")
        self.assertEqual([name for name, _ in options], ["FLAG_ACTIVITY_NEW_TASK"])
        text = '{"flags": []}'
        _, options = completions(text, text.index("[") + 1, root="intent", operation="sendBroadcast")
        self.assertTrue(options[0][0].startswith("FLAG_RECEIVER_"))

    def test_folding_hides_blocks_without_changing_the_request(self):
        request = {"operation": "sendBroadcast", "intent": {"action": "a", "extras": {
            "k": {"type": "Bundle", "value": {"x": {"type": "int", "value": 1}}}}}}
        text, folds = format_request(request), {}
        inner, cursor = toggle_fold(text, text.index('"value": {'), folds)
        self.assertIn('"value": {⋯₁}', inner)
        outer, cursor = toggle_fold(inner, inner.index('"intent"'), folds)  # The block opening on that line.
        self.assertEqual(outer, '{\n    "operation": "sendBroadcast",\n    "intent": {⋯₂}\n}')
        self.assertEqual(parse(outer, folds), request)
        self.assertEqual(expand(outer, folds), text)
        opened, cursor = toggle_fold(outer, outer.index("⋯"), folds)
        self.assertEqual(opened, inner)
        self.assertEqual(list(folds), [1])
        self.assertIsNone(toggle_fold('{"a": 1}', 3, {}))  # Nothing spans several lines.
        self.assertIsNone(toggle_fold(text, 0, {}))        # The request itself stays open.

    def test_a_marker_pasted_from_elsewhere_cannot_make_a_fold_contain_itself(self):
        text = '{\n    "a": {\n        "b": {⋯₁}\n    }\n}'
        folds = {}
        folded, cursor = toggle_fold(text, text.index('"a"'), folds)
        self.assertEqual(list(folds), [2])  # 1 is still written in the text, so it is not reused.
        self.assertEqual(expand(folded, folds), text)
        self.assertEqual(expand("{⋯₁}", {1: "[{⋯₁}]"}), "[{⋯₁}]")  # Even a corrupt table cannot loop.

    def test_parse_forgives_trailing_commas_and_reports_the_line(self):
        self.assertEqual(parse('{"a": [1, 2,], "b": {"c": "x,}",},}'), {"a": [1, 2], "b": {"c": "x,}"}})
        with self.assertRaisesRegex(ValueError, "Line 2, column"):
            parse('{"a": 1\n "b": }')
        with self.assertRaisesRegex(ValueError, "JSON object"):
            parse("[1]")

    def test_highlight_spans_are_byte_offsets_per_line(self):
        spans = highlights('{\n  "k€y": "v", "n": -1.5e3, "b": true, {⋯₁}\n}')
        self.assertEqual(spans[1][0], (2, 9, "json.key"))        # € is three bytes.
        self.assertEqual(spans[1][2], (11, 14, "json.string"))
        self.assertEqual([name for _, _, name in spans[1]][-3:], ["json.constant", "json.punct", "json.fold"])


class SenderFlagEditorTests(unittest.IsolatedAsyncioTestCase):
    async def test_column_name_has_no_type_popup_but_type_field_does(self):
        class EditorApp(App):
            def compose(self):
                yield JsonRequestEditor()

        app = EditorApp()
        async with app.run_test(size=(100, 30)) as pilot:
            editor = app.query_one(JsonRequestEditor).area
            text = '{"operation":"insert","values":{"":{"type":"String","value":"test2"}}}'
            editor.load(text)
            editor.focus()
            editor.move_cursor((0, text.index('"":') + 1))
            await pilot.press("ctrl+space")
            self.assertFalse(editor.popup.display)
            await pilot.press("t", "i", "t", "l", "e")
            self.assertEqual(parse(editor.text)["values"]["title"]["value"], "test2")
            self.assertFalse(editor.popup.display)
            editor.move_cursor((0, editor.text.index("String") + 1))
            await pilot.press("ctrl+space")
            self.assertTrue(editor.popup.display)
            self.assertTrue(any(name == "String" for name, _ in editor._matches))

    async def test_flag_picker_completes_a_json_string_with_the_keyboard(self):
        class EditorApp(App):
            def compose(self):
                yield JsonRequestEditor()

        app = EditorApp()
        async with app.run_test(size=(100, 30)) as pilot:
            editor = app.query_one(JsonRequestEditor).area
            text = '{"operation":"startActivity","intent":{"flags":["new_t"]}}'
            editor.load(text)
            editor.focus()
            editor.move_cursor((0, text.index("new_t") + len("new_t")))
            await pilot.press("ctrl+space")
            self.assertTrue(editor.popup.display)
            self.assertEqual(editor._matches[0][0], "FLAG_ACTIVITY_NEW_TASK")
            await pilot.press("enter")
            self.assertEqual(parse(editor.text)["intent"]["flags"], ["FLAG_ACTIVITY_NEW_TASK"])


if __name__ == "__main__":
    unittest.main()
