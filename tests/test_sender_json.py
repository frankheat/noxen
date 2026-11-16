import unittest

from noxen.sender import validate_request
from noxen.sender_json import (apply_completion, completions, expand, format_request, highlights, parse,
                               toggle_fold)


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
                         '        "action": null,\n        "data": null,\n        "flags": 0,\n'
                         '        "categories": [],\n        "extras": {}\n    }\n}')
        # A missing comma after the previous member is added; a typed quote pair is consumed.
        self.assertEqual(complete('{\n    "intent": {\n        "action": "x"\n        "ca|"\n    }\n}', "categories"),
                         '{\n    "intent": {\n        "action": "x",\n        "categories": [|]\n    }\n}')
        self.assertEqual(complete('{"operation": "call", "extras": {\n    St|\n}}', "String"),
                         '{"operation": "call", "extras": {\n    "|": {"type": "String", "value": ""}\n}}')
        self.assertEqual(complete('{"operation": "st|"}', "startActivity"), '{"operation": "startActivity"|}')

    def test_snippets_produce_requests_that_validate(self):
        text = complete('{\n    "operation": "sendBroadcast",\n    in|\n}', "intent").replace("|", "")
        self.assertEqual(validate_request(parse(text))["intent"]["flags"], 0)

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


if __name__ == "__main__":
    unittest.main()
