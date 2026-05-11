import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="noxen",
        description="Android runtime interception tool. Uses Frida to hook Java methods and inspect app attack-surface events in real time.",
    )
    p_proj = parser.add_mutually_exclusive_group()
    p_proj.add_argument(
        "--project",
        metavar="FILE",
        help="Open an existing project database (.noxen) and restore its history",
    )
    p_proj.add_argument(
        "--new-project",
        metavar="NAME",
        dest="new_project",
        help="Create a new project database with the given name (e.g. 'my_app')",
    )
    args = parser.parse_args()
    from noxen.app import NoxenApp
    try:
        app = NoxenApp(args)
    except (FileNotFoundError, FileExistsError) as exc:
        print(f"noxen: {exc}", file=sys.stderr)
        return 1
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
