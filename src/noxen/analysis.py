import json

try:
    from androguard.misc import AnalyzeAPK
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False


def dex_to_java_class(dex_name):
    if not dex_name.startswith("L") or not dex_name.endswith(";"):
        return dex_name
    return dex_name[1:-1].replace("/", ".")


def inherits_from(class_name, target_super, hierarchy_map):
    visited = set()
    current = class_name
    while current and current != "Ljava/lang/Object;" and current not in visited:
        if current == target_super:
            return True
        visited.add(current)
        current = hierarchy_map.get(current)
    return False


def run_analysis(apk_path, output_file):
    if not ANDROGUARD_AVAILABLE:
        print("[!] Error: 'androguard' not found.")
        return
    print(f"[*] Analyzing {apk_path}...")
    try:
        a, d_list, dx = AnalyzeAPK(apk_path)
    except Exception as e:
        print(f"[!] Analysis failed: {e}")
        return

    class_hierarchy = {}
    for dex in d_list:
        for cls in dex.get_classes():
            class_hierarchy[cls.get_name()] = cls.get_superclassname()

    hooks = []
    print("[*] Scanning classes...")
    for cls_name in class_hierarchy.keys():
        java_class = dex_to_java_class(cls_name)
        if inherits_from(cls_name, "Landroid/content/BroadcastReceiver;", class_hierarchy):
            hooks.append({"clazz": java_class, "method": "onReceive", "args": ["android.content.Context", "android.content.Intent"]})
        if inherits_from(cls_name, "Landroid/app/Service;", class_hierarchy):
            hooks.append({"clazz": java_class, "method": "onStartCommand", "args": ["android.content.Intent", "int", "int"]})
            hooks.append({"clazz": java_class, "method": "onBind", "args": ["android.content.Intent"]})

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(hooks, f, indent=2)
        print(f"[+] Written {len(hooks)} hooks to {output_file}")
    except Exception as e:
        print(f"[!] Error writing file: {e}")


def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="noxen-analyze",
        description="Analyze an APK and generate a hook configuration file for noxen.",
    )
    parser.add_argument("apk", metavar="APK", help="Path to the APK file to analyze")
    parser.add_argument(
        "-o",
        metavar="OUTPUT",
        default="customHooks.json",
        help="Output file for the generated hook definitions (default: customHooks.json)",
    )
    args = parser.parse_args()
    run_analysis(args.apk, args.o)
