import asyncio
import copy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from rich.text import Text
from textual.widgets import Input, Static

from noxen.app import NoxenApp
from noxen.rendering import format_uri_grant_flags, render_edit_context


def example_info():
    return {
        "action": "dev.noxen.playground.SELECTOR_ACTIVE_PAYLOAD", "data": None,
        "mimeType": None, "flags": 1, "categories": [], "extras": {},
        "selector": {
            "kind": "intent", "displayType": "Intent", "component": "dev.noxen.playground/.Activity1",
            "action": "dev.noxen.playground.SELECTOR_ACTIVE_ROUTE", "mimeType": "application/selector",
            "flags": 0, "categories": [],
        },
        "clipData": {
            "kind": "clipdata", "displayType": "ClipData", "label": "shared [documents]",
            "count": 1, "mimeTypes": ["text/uri-list"], "items": [
                {"kind": "clipitem", "displayType": "Item", "uri": "content://example/report-1"},
            ],
        },
    }


def context_text(info, attack_surface):
    return Text.from_markup("\n\n".join(render_edit_context(info, attack_surface).values())).plain


def widget_context(app):
    return "\n".join(str(app.query_one(f"#ef_{key}_body", Static).render()) for key in ("routing", "selector", "clip"))


class EditContextRenderingTests(unittest.TestCase):
    def test_broadcast_editor_has_readonly_call_and_components_without_routing(self):
        info = example_info()
        surface = {"broadcastComponents": {}, "broadcastPermission": {
            "name": "example.RECEIVE", "level": "signature"}, "intentExplicit": True}
        original = copy.deepcopy(info)
        sections = render_edit_context(info, surface, "sendBroadcast")
        self.assertNotIn("routing", sections)
        self.assertIn("Receiver Perm", Text.from_markup(sections["call"]).plain)
        self.assertIn("example.RECEIVE", Text.from_markup(sections["call"]).plain)
        self.assertIn("None", Text.from_markup(sections["component"]).plain)
        self.assertNotIn("call", render_edit_context(info, surface, "getBroadcast"))
        self.assertEqual(info, original)

    def test_activity_context_contains_only_actual_components_and_no_routing(self):
        info = example_info()
        info["component"] = "dev.noxen.playground/.MainActivity"
        surface = {
            "intentExplicit": True, "selectorRoutingRole": "ignored",
            "activityComponents": {
                "base": {"component": info["component"], "exported": True},
                "selector": {"component": info["selector"]["component"], "exported": False},
            },
        }
        sections = render_edit_context(info, surface, "startActivity")
        self.assertNotIn("routing", sections)
        base = Text.from_markup(sections["component"]).plain
        selector = Text.from_markup(sections["selector"]).plain
        self.assertIn(info["component"], base)
        self.assertIn("true", base)
        self.assertIn(info["selector"]["component"], selector)
        self.assertIn("false", selector)
        self.assertNotIn("IGNORED", selector)
        info["component"] = None
        base = Text.from_markup(render_edit_context(info, surface, "startActivity")["component"]).plain
        self.assertIn("None", base)
        self.assertNotIn("Exported", base)

    def test_reuses_trees_without_stale_outer_grants_or_mutating_capture(self):
        info = example_info()
        original = copy.deepcopy(info)
        rendered = context_text(info, {"selectorRoutingRole": "active"})
        self.assertEqual(list(render_edit_context(info, {})), ["selector", "clipData"])
        for value in ("ACTIVE",
                      "application/selector", "content://example/report-1", "shared [documents]"):
            self.assertIn(value, rendered)
        self.assertNotIn("Grant flags", rendered)
        self.assertLess(rendered.index("ACTIVE"), rendered.index("Component"))
        self.assertIn("Component       dev.noxen.playground/.Activity1", rendered)
        self.assertNotIn("  Component", rendered)
        self.assertEqual(info, original)

    def test_routing_metadata_requires_observed_role_and_is_separate_from_selector(self):
        for role in ("active", "ignored", "redundant", None, "unknown"):
            for present in (True, False):
                with self.subTest(role=role, selector=present):
                    info = example_info()
                    if not present:
                        info["selector"] = None
                    rendered = context_text(info, {"selectorRoutingRole": role})
                    sections = render_edit_context(info, {"selectorRoutingRole": role})
                    self.assertEqual("routing" in sections, present and role in {"active", "ignored", "redundant"})
                    self.assertNotIn("Routing", sections.get("selector", ""))
                    self.assertNotIn("[dim]Selector", sections.get("selector", ""))
                    self.assertNotIn("unchanged", rendered)
                    self.assertNotIn("not the fields above", rendered)

    def test_absent_context_and_unknown_receiver_routing_are_not_invented(self):
        self.assertEqual(render_edit_context({}, {}), {})
        rendered = context_text(example_info(), {})
        self.assertNotIn("Routing role", rendered)

    def test_grant_decoding(self):
        for flags, expected in ((None, "unavailable"), (0, "none"), (1, "READ"), (2, "WRITE"),
                                (0xC3, "READ | WRITE | PERSISTABLE | PREFIX"),
                                (-1, "READ | WRITE | PERSISTABLE | PREFIX"), (0x10000000, "none")):
            with self.subTest(flags=flags):
                self.assertEqual(format_uri_grant_flags(flags), expected)

    def test_selector_roles_and_nested_clipdata_are_visible(self):
        info = example_info()
        info["clipData"]["items"][0]["intent"] = {
            "kind": "intent", "displayType": "Intent", "action": "CLIP_NESTED", "flags": 0,
            "clipData": {"kind": "clipdata", "displayType": "ClipData", "count": 1,
                         "mimeTypes": ["text/plain"], "items": [
                             {"kind": "clipitem", "displayType": "Item", "text": "inner text"},
                         ]},
        }
        for role, label in (("active", "ACTIVE"), ("ignored", "IGNORED"), ("redundant", "REDUNDANT")):
            with self.subTest(role=role):
                rendered = context_text(info, {"selectorRoutingRole": role})
                self.assertIn(f"{'Selector':<16}{label}", rendered)
                self.assertIn("CLIP_NESTED", rendered)
                self.assertIn("inner text", rendered)

    def test_unreadable_truncated_and_cyclic_nodes_remain_bounded(self):
        info = example_info()
        info["selector"] = {"kind": "status", "value": "selector could not be read"}
        clip = info["clipData"]
        clip["omitted"] = 10
        clip["items"].append({"kind": "clipitem", "intent": {
            "kind": "intent", "clipData": clip, "flags": 0,
        }})
        result = context_text(info, {})
        self.assertIn("selector could not be read", result)
        self.assertLess(len(result.splitlines()), 300)


class EditContextUITests(unittest.IsolatedAsyncioTestCase):
    async def test_activity_editor_hides_routing_and_resets_component_context(self):
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(
                new_project=str(Path(directory) / "activity.noxen"), project=None, skip_device_scan=True,
            ))
            async with app.run_test(size=(100, 45)) as pilot:
                app.query_one("#main_tabs").active = "tab_intercept"
                info = example_info()
                info["component"] = "dev.noxen.playground/.MainActivity"
                app._current_intercepted_entry = {
                    "id": 1, "method": "startActivity", "intent": info,
                    "attackSurface": {"activityComponents": {"base": {
                        "component": info["component"], "exported": True,
                    }}},
                }
                app._enter_edit_mode()
                await pilot.pause()
                self.assertFalse(app.query_one("#ef_routing_section").display)
                component = app.query_one("#ef_component_body", Static)
                self.assertTrue(component.display)
                self.assertIn(info["component"], str(component.render()))
                self.assertIn("Exported", str(component.render()))
                app._current_intercepted_entry = {
                    "method": "startService", "attackSurface": {"intentExplicit": False},
                }
                app._populate_edit_form(example_info())
                await pilot.pause()
                self.assertFalse(component.display)
                self.assertTrue(app.query_one("#ef_routing_section").display)
                app._current_intercepted_entry = {
                    "method": "sendBroadcast", "attackSurface": {
                        "broadcastComponents": {}, "broadcastPermission": None,
                    },
                }
                app._populate_edit_form(example_info())
                await pilot.pause()
                self.assertFalse(app.query_one("#ef_routing_section").display)
                call = app.query_one("#ef_call_body", Static)
                self.assertTrue(call.display)
                self.assertIn("Receiver Perm", str(call.render()))
                app._current_intercepted_entry = {"method": "startActivity", "attackSurface": {}}
                app._populate_edit_form(example_info())
                await pilot.pause()
                self.assertFalse(call.display)

    async def test_section_spacing_with_empty_populated_and_removed_rows(self):
        asyncio.get_running_loop().slow_callback_duration = 1.0
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(
                new_project=str(Path(directory) / "spacing.noxen"), project=None, skip_device_scan=True,
            ))
            async with app.run_test(size=(110, 60)) as pilot:
                app.query_one("#main_tabs").active = "tab_intercept"
                app._current_intercepted_entry = {"id": 1, "intent": example_info()}
                app._enter_edit_mode()
                for theme in ("noxen-dark", "noxen-light"):
                    app.theme = theme
                    for count in (0, 1, 3):
                        with self.subTest(theme=theme, count=count):
                            info = example_info()
                            info["categories"] = [f"category.{i}" for i in range(count)]
                            app._populate_edit_form(info)
                            for i in range(count):
                                app._add_edit_extra_row(f"key_{i}", "string", "value", True)
                            await pilot.pause()

                            def assert_spacing():
                                rules = [r for r in app.query("#edit_form Rule") if r.parent.id != "ef_routing_section"]
                                categories = list(app.query(".ef_cat_row"))
                                extras = list(app.query(".ef_x_row"))
                                category_end = categories[-1] if categories else app.query_one("#ef_categories_header")
                                extra_end = extras[-1] if extras else app.query_one(".ef_x_columns")
                                for last, rule in ((app.query_one("#ef_grant_row"), rules[0]),
                                                   (category_end, rules[1]), (extra_end, rules[2])):
                                    self.assertEqual(rule.region.y - last.region.bottom, 1)
                                for rows in (categories, extras):
                                    for previous, following in zip(rows, rows[1:]):
                                        self.assertEqual(following.region.y - previous.region.bottom, 1)
                                if categories:
                                    self.assertEqual(categories[0].region.y - app.query_one("#ef_categories_header").region.bottom, 1)
                                if extras:
                                    self.assertEqual(extras[0].region.y - app.query_one(".ef_x_columns").region.bottom, 0)

                            assert_spacing()
                            # Check both ends, including a new first row after deletion.
                            while app.query(".ef_cat_row") or app.query(".ef_x_row"):
                                for selector in (".ef_cat_row", ".ef_x_row"):
                                    rows = list(app.query(selector))
                                    if rows:
                                        await rows[0 if len(rows) % 2 else -1].remove()
                                await pilot.pause()
                                assert_spacing()

    async def test_headers_columns_and_section_order_in_both_themes_and_narrow_layout(self):
        asyncio.get_running_loop().slow_callback_duration = 1.0
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(
                new_project=str(Path(directory) / "layout.noxen"), project=None, skip_device_scan=True,
            ))
            async with app.run_test(size=(110, 52)) as pilot:
                app.query_one("#main_tabs").active = "tab_intercept"
                info = example_info()
                info["categories"] = ["android.intent.category.DEFAULT"]
                info["extras"] = {"existing": {"type": "java.lang.String", "value": "value"}}
                app._current_intercepted_entry = {
                    "id": 1, "intent": info, "attackSurface": {"selectorRoutingRole": "active"},
                }
                app._enter_edit_mode()
                app._add_edit_extra_row("new_key", "string", "value", True)
                for theme in ("noxen-dark", "noxen-light"):
                    app.theme = theme
                    for width in (110, 72):
                        with self.subTest(theme=theme, width=width):
                            await pilot.resize_terminal(width, 52)
                            await pilot.pause()
                            headers = list(app.query(".ef_section"))
                            self.assertEqual([str(h.render()) for h in headers],
                                             ["Routing", "Base Intent", "Categories", "Extras", "Selector", "ClipData"])
                            self.assertEqual(len({str(h.styles.color) for h in headers}), 1)
                            self.assertEqual(len({h.content_region.x for h in headers}), 1)
                            field = app.query_one("#ef_action", Input)
                            grants = app.query_one("#ef_grant_flags", Static)
                            self.assertEqual(field.content_region.x, grants.content_region.x)
                            remove_buttons = list(app.query(".ef_x_rm"))
                            self.assertEqual(len(remove_buttons), 3)
                            for button in remove_buttons:
                                self.assertEqual(button.region.width, 3)
                                self.assertEqual(button.parent.content_region.right - button.region.right, 2)
                            remove_header = app.query_one(".ef_x_remove_header")
                            self.assertEqual(remove_header.region.x, remove_buttons[-1].region.x)
                            for key in ("selector", "clip"):
                                body = app.query_one(f"#ef_{key}_body", Static)
                                self.assertEqual(body.content_region.x, headers[0].content_region.x)
                                self.assertEqual(field.content_region.x - body.content_region.x, 16)

    async def test_draft_flags_mime_commands_cancel_and_next_capture(self):
        asyncio.get_running_loop().slow_callback_duration = 1.0
        with tempfile.TemporaryDirectory() as directory:
            app = NoxenApp(SimpleNamespace(
                new_project=str(Path(directory) / "context.noxen"), project=None, skip_device_scan=True,
            ))
            async with app.run_test(size=(100, 38)) as pilot:
                app.query_one("#main_tabs").active = "tab_intercept"
                original = example_info()
                capture = copy.deepcopy(original)
                app._current_intercepted_entry = {
                    "id": 1, "intent": original, "attackSurface": {
                        "selectorRoutingRole": "active", "intentExplicit": True, "routingSource": "selector",
                    },
                }
                app._current_intercept_id = 1
                app._enter_edit_mode()
                await pilot.pause()
                self.assertTrue(app.query_one("#ef_routing_section").display)
                self.assertIn("Derived from capture", str(app.query_one("#ef_routing_section .ef_section_meta").render()))
                self.assertTrue(app.query_one("#ef_readonly_context").display)
                self.assertEqual(len(app.query("#ef_mime_scope")), 0)
                context = widget_context(app)
                self.assertIn("ACTIVE", context)
                self.assertIn("EXPLICIT", context)
                self.assertIn("content://example/report-1", context)
                self.assertIn("READ", str(app.query_one("#ef_grant_flags", Static).render()))

                flags = app.query_one("#ef_flags", Input)
                for value, expected in (("0x0", "none"), ("0x3", "READ | WRITE"),
                                        ("-1", "PERSISTABLE | PREFIX"), ("0x", "unavailable")):
                    flags.value = value
                    await pilot.pause()
                    self.assertIn(expected, str(app.query_one("#ef_grant_flags", Static).render()))
                with self.assertRaisesRegex(ValueError, "Flags must be"):
                    app._collect_edit_mods()

                flags.value = "0x1"
                app.query_one("#ef_mime", Input).value = "application/pdf"
                await pilot.pause()
                self.assertEqual(app._collect_edit_mods(), [("mime", "", "application/pdf", "")])
                draft = app._collect_edit_draft()
                self.assertEqual(draft["selector"], capture["selector"])
                self.assertEqual(draft["clipData"], capture["clipData"])
                self.assertEqual(widget_context(app), context)

                self.assertIsNone(app._apply_command_mod_to_editor(("flag_add", "", "2", "")))
                await pilot.pause()
                self.assertIn("READ | WRITE", str(app.query_one("#ef_grant_flags", Static).render()))
                self.assertEqual(app._current_intercepted_entry["intent"], capture)
                app._exit_edit_mode()
                self.assertEqual(app._current_intercepted_entry["intent"], capture)

                app._current_intercepted_entry = {
                    "id": 2, "intent": {"flags": 0, "extras": {}, "package": None},
                    "attackSurface": {"intentExplicit": False, "routingSource": "base"},
                }
                app._enter_edit_mode()
                await pilot.pause()
                self.assertTrue(app.query_one("#ef_routing_section").display)
                self.assertIn("IMPLICIT", str(app.query_one("#ef_routing_body", Static).render()))
                self.assertFalse(app.query_one("#ef_readonly_context").display)
                app._exit_edit_mode()

                app._current_intercepted_entry = {"id": 3, "intent": {"flags": 0, "extras": {}}}
                app._enter_edit_mode()
                await pilot.pause()
                self.assertFalse(app.query_one("#ef_readonly_context").display)
                self.assertFalse(app.query_one("#ef_routing_section").display)
                self.assertFalse(app.query_one("#ef_grant_row").display)
