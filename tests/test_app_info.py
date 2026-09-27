import unittest

from noxen.app_info import (
    component_access,
    component_counts,
    component_enabled,
    component_row,
    filter_components,
    filter_permissions,
    format_component_permission,
    format_permission,
    is_exposed,
    overview_sections,
    permission_access,
    permission_row,
    provider_access,
    render_component_detail,
)


SNAPSHOT = {
    "identity": {
        "package": "com.frankheat.noxen.playground",
        "label": "noxen playground",
        "versionName": "1.0",
        "versionCode": "1",
        "uid": 10148,
        "pid": 31625,
        "processName": "com.frankheat.noxen.playground",
        "sharedUserId": None,
        "installer": None,
        "firstInstallTime": 1789804892915,
        "lastUpdateTime": 1789804892915,
    },
    "build": {
        "deviceSdk": 31, "targetSdk": 36, "minSdk": 24, "compileSdk": 36,
        "debuggable": True, "allowBackup": True, "testOnly": False,
        "extractNativeLibs": False, "cleartextPermitted": False, "nscPresent": False,
    },
    "signing": {"sha256": ["0A71D542326A03620D0378D1E872BC17"], "multipleSigners": False},
    "permissions": [
        {"name": "com.x.MY_CUSTOM_PERMISSION", "source": "requested", "granted": True, "level": "normal",
         "definedBy": "com.x"},
        {"name": "com.x.SIG_PERM", "source": "requested", "granted": True, "level": "signature",
         "definedBy": "com.x"},
        {"name": "com.x.MY_CUSTOM_PERMISSION", "source": "defined", "granted": None, "level": "normal",
         "definedBy": "com.x"},
    ],
    "components": [
        {"name": "com.x.Receiver2", "type": "receiver", "exported": True,
         "permission": {"name": "com.x.MY_CUSTOM_PERMISSION", "level": "normal"},
         "enabled": True, "enabledRuntime": 0, "processName": "com.x", "directBootAware": False},
        {"name": "com.x.Receiver1", "type": "receiver", "exported": True, "permission": None,
         "enabled": True, "enabledRuntime": 0, "processName": "com.x", "directBootAware": False},
        {"name": "com.x.Activity1", "type": "activity", "exported": False, "permission": None,
         "enabled": True, "enabledRuntime": 0, "processName": "com.x", "directBootAware": False,
         "launchMode": 0, "taskAffinity": "com.x", "targetActivity": None},
        {"name": "com.x.SecretProvider", "type": "provider", "exported": True,
         "permission": None, "enabled": True, "enabledRuntime": 2, "processName": "com.x",
         "directBootAware": False, "authority": "com.x.files", "readPermission": None,
         "writePermission": {"name": "com.x.SIG_PERM", "level": "signature", "definedBy": "com.x"},
         "pathPermissions": [], "grantUriPermissions": True, "grantUriPatterns": [], "multiprocess": False},
    ],
}


class AppInfoTests(unittest.TestCase):
    def test_component_enabled_runtime_override(self):
        self.assertTrue(component_enabled({"enabled": True, "enabledRuntime": 0}))
        self.assertFalse(component_enabled({"enabled": True, "enabledRuntime": 2}))
        self.assertTrue(component_enabled({"enabled": False, "enabledRuntime": 1}))

    def test_is_exposed(self):
        self.assertTrue(is_exposed({"exported": True, "permission": None}))
        self.assertTrue(is_exposed({"exported": True, "permission": {"level": "normal"}}))
        self.assertFalse(is_exposed({"exported": True, "permission": {"level": "signature"}}))
        self.assertFalse(is_exposed({"exported": False, "permission": None}))

    def test_format_permission(self):
        self.assertEqual(format_permission(None), "—")
        self.assertEqual(format_permission({"name": "com.x.P", "level": "normal"}), "com.x.P (normal)")

    def test_rows(self):
        row = component_row(SNAPSHOT["components"][0])
        self.assertEqual(row, ["com.x.Receiver2", "receiver", "yes", "open", "yes",
                               "com.x.MY_CUSTOM_PERMISSION (normal)"])
        # not exported → no access class
        self.assertEqual(component_row(SNAPSHOT["components"][2])[3], "—")
        # provider is runtime-disabled (enabledRuntime=2)
        self.assertEqual(component_row(SNAPSHOT["components"][3])[4], "no")
        self.assertEqual(component_row(SNAPSHOT["components"][3])[5], "read: — · write: signature")
        self.assertEqual(permission_row(SNAPSHOT["permissions"][0]),
                         ["com.x.MY_CUSTOM_PERMISSION", "requested", "yes", "normal", "com.x"])
        self.assertEqual(permission_row(SNAPSHOT["permissions"][2])[2], "—")  # defined → granted n/a

    def test_filter_components(self):
        comps = SNAPSHOT["components"]
        self.assertEqual(len(filter_components(comps, type_filter="receiver")), 2)
        exposed = filter_components(comps, exposed_only=True)
        names = {c["name"] for c in exposed}
        self.assertEqual(names, {"com.x.Receiver2", "com.x.Receiver1", "com.x.SecretProvider"})  # exported + no/normal perm
        self.assertEqual(len(filter_components(comps, query="activity1")), 1)

    def test_filter_permissions(self):
        perms = SNAPSHOT["permissions"]
        self.assertEqual(len(filter_permissions(perms, source="defined")), 1)
        self.assertEqual(len(filter_permissions(perms, query="sig")), 1)

    def test_component_counts(self):
        counts = component_counts(SNAPSHOT["components"])
        self.assertEqual(counts["receiver"], 2)
        self.assertEqual(counts["provider"], 1)
        self.assertEqual(counts["exported"], 3)
        self.assertEqual((counts["open"], counts["weak"], counts["protected"]), (3, 0, 0))

    def test_overview_sections(self):
        sections = dict((title, rows) for title, rows in overview_sections(SNAPSHOT))
        self.assertIn("IDENTITY", sections)
        identity = dict(sections["IDENTITY"])
        self.assertEqual(identity["Package"], "com.frankheat.noxen.playground")
        self.assertEqual(identity["Version"], "1.0 (1)")
        build = dict(sections["BUILD & FLAGS"])
        self.assertEqual(build["Debuggable"], "yes")
        self.assertEqual(build["Cleartext traffic"], "no")
        summary = dict(sections["SUMMARY"])
        self.assertEqual(summary["Exported"], "3")
        self.assertEqual(summary["Access"], "open 3 · weak 0 · protected 0")
        self.assertEqual(summary["Permissions"], "requested 2 (granted 2) · defined 1")

    def test_render_component_detail_provider(self):
        rendered = render_component_detail(SNAPSHOT["components"][3])
        self.assertIn("[bold]com.x.SecretProvider[/bold]", rendered)
        self.assertIn("Authority", rendered)
        self.assertIn("com.x.files", rendered)
        self.assertIn("Grant URI perms", rendered)
        self.assertIn("Write permission", rendered)


def perm(name, level, defined_by="com.x"):
    return {"name": name, "level": level, "definedBy": defined_by}


def provider(read=None, write=None, paths=None, exported=True):
    return {"name": "com.x.P", "type": "provider", "exported": exported,
            "permission": None, "readPermission": read, "writePermission": write,
            "pathPermissions": paths or [], "grantUriPermissions": False, "grantUriPatterns": []}


class AccessTests(unittest.TestCase):
    def test_permission_access_by_level(self):
        self.assertEqual(permission_access(None), "open")
        for level in ("normal", "unresolved", "unknown"):
            self.assertEqual(permission_access(perm("p", level)), "open", level)
        self.assertEqual(permission_access(perm("p", "dangerous")), "weak")
        for level in ("signature", "signatureOrSystem", "internal"):
            self.assertEqual(permission_access(perm("p", level)), "protected", level)

    def test_single_permission_components(self):
        receiver = {"type": "receiver", "exported": True}
        self.assertEqual(component_access({**receiver, "permission": perm("p", "dangerous")}), "weak")
        self.assertFalse(is_exposed({**receiver, "permission": perm("p", "dangerous")}))
        # an unresolved permission may be claimable by any app → open
        self.assertTrue(is_exposed({**receiver, "permission": perm("p", "unresolved", None)}))
        self.assertIsNone(component_access({**receiver, "exported": False, "permission": None}))

    def test_provider_is_open_when_one_direction_is(self):
        comp = provider(read=perm("com.x.READ", "signature"))
        self.assertEqual(provider_access(comp), {"read": "protected", "write": "open"})
        self.assertEqual(component_access(comp), "open")

    def test_provider_protected_in_both_directions(self):
        sig = perm("com.x.SIG", "signature")
        comp = provider(read=sig, write=sig)
        self.assertEqual(component_access(comp), "protected")
        self.assertFalse(is_exposed(comp))

    def test_path_permission_is_an_alternative_grant(self):
        sig = perm("com.x.SIG", "signature")
        public_read = {"match": "pathPrefix", "path": "/public",
                       "readPermission": perm("com.x.NORMAL", "normal"), "writePermission": None}
        comp = provider(read=sig, write=sig, paths=[public_read])
        # the /public path opens reads; writes stay protected
        self.assertEqual(provider_access(comp), {"read": "open", "write": "protected"})
        self.assertTrue(is_exposed(comp))

    def test_provider_permission_cell(self):
        sig = perm("com.x.SIG", "signature")
        dng = perm("com.x.DNG", "dangerous")
        path = {"match": "path", "path": "/a", "readPermission": sig, "writePermission": None}
        self.assertEqual(format_component_permission(provider()), "—")
        # one permission for both directions (android:permission) → shown like any component
        self.assertEqual(format_component_permission(provider(read=sig, write=sig)), "com.x.SIG (signature)")
        # otherwise a per-direction level summary; names live in the detail panel
        self.assertEqual(format_component_permission(provider(read=sig)), "read: signature · write: —")
        self.assertEqual(format_component_permission(provider(read=sig, write=dng)),
                         "read: signature · write: dangerous")
        self.assertEqual(format_component_permission(provider(read=sig, write=sig, paths=[path])),
                         "read: signature · write: signature · +1 path")
        self.assertEqual(format_component_permission(provider(paths=[path, path])),
                         "read: — · write: — · +2 paths")

    def test_format_permission_names_third_party_definer(self):
        foreign = perm("com.y.P", "signature", "com.y")
        self.assertEqual(format_permission(foreign), "com.y.P (signature)")
        self.assertEqual(format_permission(foreign, "com.x"), "com.y.P (signature · defined by com.y)")
        # own package and the platform are not worth calling out
        self.assertEqual(format_permission(perm("a", "normal", "com.x"), "com.x"), "a (normal)")
        self.assertEqual(format_permission(perm("a", "dangerous", "android"), "com.x"), "a (dangerous)")

    def test_search_matches_provider_permissions(self):
        comp = provider(read=perm("com.x.READ_DATA", "signature"))
        self.assertEqual(filter_components([comp], query="read_data"), [comp])

    def test_detail_shows_directions_paths_and_unresolved_note(self):
        path = {"match": "pathPrefix", "path": "/public",
                "readPermission": perm("com.x.GHOST", "unresolved", None), "writePermission": None}
        comp = provider(read=perm("com.x.SIG", "signature"), write=perm("com.x.DNG", "dangerous"),
                        paths=[path])
        rendered = render_component_detail(comp, "com.x")
        self.assertIn("(read: open · write: weak)", rendered)
        self.assertIn("pathPrefix /public", rendered)
        self.assertIn("com.x.GHOST (unresolved)", rendered)
        self.assertIn("adb shell pm list permissions -f", rendered)

    def test_overview_counts_unresolved_requested_permissions(self):
        info = {"permissions": [{"name": "com.x.GHOST", "source": "requested", "granted": False,
                                 "level": "unresolved", "definedBy": None}], "components": []}
        summary = dict(dict(overview_sections(info))["SUMMARY"])
        self.assertEqual(summary["Permissions"], "requested 1 (granted 0) · defined 0 · unresolved 1")


if __name__ == "__main__":
    unittest.main()
