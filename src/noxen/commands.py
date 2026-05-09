from dataclasses import dataclass

from textual.suggester import Suggester


HELP_MENU = {
    "Intent Actions": [
        ("forward", "Forward the intercepted intent"),
        ("f", "Forward the intercepted intent"),
        ("drop", "Drop/block the intercepted intent"),
        ("d", "Drop/block the intercepted intent"),
    ],
    "Intent Modifications": [
        ("action <val>", "Set Intent Action"),
        ("data <uri>", "Set Intent Data URI"),
        ("+cat <val>", "Add Category"),
        ("-cat <val>", "Remove Category"),
        ("+flag <int>", "Add Flag"),
        ("-flag <int>", "Remove Flag"),
        ("+x (type) <k> <v>", "Add Extra (type optional, default: string)"),
        ("  types:", "int, bool, float, long, double, string"),
        ("-x <k>", "Remove Extra"),
    ],
    "Intercept Commands": [
        ("/intercept on", "Enable global Noxen interception"),
        ("/intercept off", "Disable global Noxen interception"),
        ("/intercept status", "Show interception state"),
        ("/stack on", "Enable stack trace display"),
        ("/stack off", "Disable stack trace display"),
        ("/stack <number>", "Set number of stack frames to show"),
        ("/filter list", "List active intercept filters"),
        ("/filter add ignore <rule>", "Add intercept blacklist rule"),
        ("/filter add focus <rule>", "Add intercept whitelist rule"),
        ("/filter remove <id>", "Remove intercept filter by ID"),
    ],
    "App Commands": [
        ("/help", "Show help menu"),
        ("/quit", "Exit application"),
        ("/theme", "Toggle dark/light theme"),
        ("/clear history", "Clear all history entries"),
    ],
    "Export / Save": [
        ("/export entries", "Export all history entries to JSON"),
        ("/export filtered entries", "Export filtered history entries to JSON"),
        ("/save history filters", "Save history tab filters to file"),
        ("/save intercept filters", "Save intercept tab filters to file"),
    ],
}

HELP_MENU_HISTORY = {
    "Intercept Commands": [
        ("/intercept on", "Enable global Noxen interception"),
        ("/intercept off", "Disable global Noxen interception"),
        ("/intercept status", "Show interception state"),
    ],
    "History Commands": [
        ("/stack on", "Enable stack trace in history detail"),
        ("/stack off", "Disable stack trace in history detail"),
        ("/stack <number>", "Set number of stack frames to show"),
        ("/filter list", "List active history filters"),
        ("/filter add ignore <rule>", "Add history blacklist rule"),
        ("/filter add focus <rule>", "Add history whitelist rule"),
        ("/filter remove <id>", "Remove history filter by ID"),
    ],
    "System": [
        ("/help", "Show help menu"),
        ("/quit", "Exit application"),
        ("/theme", "Toggle dark/light theme"),
        ("/clear history", "Clear all history entries"),
    ],
    "Export / Save": [
        ("/export entries", "Export all history entries to JSON"),
        ("/export filtered entries", "Export filtered history entries to JSON"),
        ("/save history filters", "Save history tab filters to file"),
        ("/save intercept filters", "Save intercept tab filters to file"),
    ],
}

SUGGESTION_TEMPLATE_WIDTH = 32

INTENT_COMMAND_BASES = frozenset({
    "forward", "f", "drop", "d",
    "action", "data",
    "+cat", "-cat", "+flag", "-flag", "+x", "-x",
})

VALID_FILTER_TYPES = frozenset({"ignore", "focus"})


@dataclass(frozen=True)
class ParsedCommand:
    raw: str
    parts: list[str]
    base: str


@dataclass(frozen=True)
class ParsedStackCommand:
    action: str
    depth: int | None = None


@dataclass(frozen=True)
class ParsedFilterCommand:
    action: str
    filter_type: str | None = None
    rule_parts: list[str] | None = None
    filter_id: str | None = None


@dataclass(frozen=True)
class ParsedInterceptCommand:
    action: str


@dataclass(frozen=True)
class ParsedExportCommand:
    filtered: bool


@dataclass(frozen=True)
class ParsedSaveCommand:
    target: str
    file_label: str


@dataclass(frozen=True)
class ParsedClearCommand:
    target: str


@dataclass(frozen=True)
class SubmittedCommand:
    should_complete: bool
    command: str


def parse_command(text: str) -> ParsedCommand | None:
    parts = text.split()
    if not parts:
        return None
    return ParsedCommand(raw=text, parts=parts, base=parts[0].lower())


def parse_intent_command(text: str) -> ParsedCommand | None:
    command = parse_command(text)
    if command is None or command.base.startswith("/") or command.base not in INTENT_COMMAND_BASES:
        return None
    return command


def parse_stack_command(parts: list[str]) -> ParsedStackCommand | None:
    if len(parts) < 2:
        return ParsedStackCommand("status")

    arg = parts[1].lower()
    if arg in ("on", "off"):
        return ParsedStackCommand(arg)
    if arg.isdigit():
        return ParsedStackCommand("depth", int(arg))
    return None


def parse_filter_command(parts: list[str]) -> ParsedFilterCommand | None:
    if len(parts) < 2:
        return None

    action = parts[1].lower()
    if action == "list":
        return ParsedFilterCommand("list")

    if action == "add":
        if len(parts) < 4 or parts[2].lower() not in VALID_FILTER_TYPES:
            return None
        return ParsedFilterCommand("add", filter_type=parts[2].lower(), rule_parts=parts[3:])

    if action == "remove":
        if len(parts) < 3:
            return None
        return ParsedFilterCommand("remove", filter_id=parts[2])

    return None


def parse_intercept_command(parts: list[str]) -> ParsedInterceptCommand | None:
    if len(parts) < 2:
        return ParsedInterceptCommand("status")

    action = parts[1].lower()
    if action in ("on", "off", "status"):
        return ParsedInterceptCommand(action)
    return None


def parse_export_command(parts: list[str]) -> ParsedExportCommand | None:
    args = [part.lower() for part in parts[1:]]
    if args == ["entries"]:
        return ParsedExportCommand(filtered=False)
    if args == ["filtered", "entries"]:
        return ParsedExportCommand(filtered=True)
    return None


def parse_save_command(parts: list[str]) -> ParsedSaveCommand | None:
    args = [part.lower() for part in parts[1:]]
    if args == ["history", "filters"]:
        return ParsedSaveCommand(target="history", file_label="history_filters")
    if args == ["intercept", "filters"]:
        return ParsedSaveCommand(target="intercept", file_label="intercept_filters")
    return None


def parse_theme_command(parts: list[str]) -> bool:
    return len(parts) == 1


def parse_clear_command(parts: list[str]) -> ParsedClearCommand | None:
    args = [part.lower() for part in parts[1:]]
    if args == ["history"]:
        return ParsedClearCommand(target="history")
    return None


def build_completions(menu):
    result = []
    for _category, entries in menu.items():
        for command, description in entries:
            if command.startswith(" "):
                continue
            for alias in command.split(","):
                result.append((alias.strip(), description))
    return result


INTERCEPT_COMPLETIONS = build_completions(HELP_MENU)
HISTORY_COMPLETIONS = build_completions(HELP_MENU_HISTORY)


def command_fill(template: str) -> str:
    indices = [template.find(separator) for separator in ("<", "(")]
    indices = [index for index in indices if index != -1]
    if indices:
        return template[:min(indices)].rstrip() + " "
    return template


def format_completion_option(template: str, description: str) -> str:
    return f"{template:<{SUGGESTION_TEMPLATE_WIDTH}} {description}"


def completion_fill_from_prompt(prompt) -> str:
    template = str(prompt)[:SUGGESTION_TEMPLATE_WIDTH].strip()
    return command_fill(template)


def matching_completions(completions, value: str):
    if not value:
        return []
    prefix = value.lower()
    return [
        (template, description)
        for template, description in completions
        if template.lower().startswith(prefix)
    ]


def resolve_submitted_command(value: str, suggestion: str | None) -> SubmittedCommand:
    command = value.strip()
    if suggestion is None:
        return SubmittedCommand(should_complete=False, command=command)
    if suggestion.endswith(" ") and suggestion.strip() != command:
        return SubmittedCommand(should_complete=True, command=suggestion)
    return SubmittedCommand(should_complete=False, command=suggestion.strip())


class CommandSuggester(Suggester):
    def __init__(self, completions, use_cache=True):
        super().__init__(use_cache=use_cache, case_sensitive=False)
        self._completions = completions

    async def get_suggestion(self, value: str) -> str | None:
        matches = matching_completions(self._completions, value)
        if not matches:
            return None
        template, _description = matches[0]
        return command_fill(template)
