import unittest

from noxen.app_info import (
    component_counts,
    component_enabled,
    component_row,
    filter_components,
    filter_permissions,
    format_permission,
    is_exposed,
    overview_sections,
    permission_row,
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
        {"name": "com.x.MY_CUSTOM_PERMISSION", "source": "requested", "granted": True, "level": "normal"},
        {"name": "com.x.SIG_PERM", "source": "requested", "granted": True, "level": "signature"},
        {"name": "com.x.MY_CUSTOM_PERMISSION", "source": "defined", "granted": None, "level": "normal"},
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
         "writePermission": "com.x.SIG_PERM", "grantUriPermissions": True, "multiprocess": False},
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
        self.assertEqual(row, ["com.x.Receiver2", "receiver", "yes", "com.x.MY_CUSTOM_PERMISSION (normal)", "yes"])
        # provider is runtime-disabled (enabledRuntime=2)
        self.assertEqual(component_row(SNAPSHOT["components"][3])[4], "no")
        self.assertEqual(permission_row(SNAPSHOT["permissions"][0]), ["com.x.MY_CUSTOM_PERMISSION", "requested", "yes", "normal"])
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
        self.assertEqual(counts["exposed"], 3)

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
        self.assertEqual(summary["Exposed"], "3")

    def test_render_component_detail_provider(self):
        rendered = render_component_detail(SNAPSHOT["components"][3])
        self.assertIn("[bold]com.x.SecretProvider[/bold]", rendered)
        self.assertIn("Authority", rendered)
        self.assertIn("com.x.files", rendered)
        self.assertIn("Grant URI perms", rendered)
        self.assertIn("Write permission", rendered)


if __name__ == "__main__":
    unittest.main()
