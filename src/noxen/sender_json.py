"""JSON editing support for Sender requests: tokens, cursor context, completions and folds.

Pure text logic. The widget lives in `sender_json_editor`; `validate_request`
stays authoritative for what a request may contain.
"""

import json
import re

from noxen.sender import INTENT_OPERATIONS, OPERATIONS, PROVIDER_OPERATIONS

INDENT = "    "
SUBSCRIPT = str.maketrans("0123456789", "₀₁₂₃₄₅₆₇₈₉")
FOLD = re.compile(r"([\{\[])⋯([₀-₉]+)[\}\]]")
TOKEN = re.compile(r"""
    (?P<fold>[\{\[]⋯[₀-₉]+[\}\]])
  | (?P<string>"(?:[^"\\\n]|\\.)*"?)
  | (?P<number>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)
  | (?P<constant>\b(?:true|false|null)\b)
  | (?P<punct>[{}\[\]:,])
  | (?P<word>[A-Za-z_][\w\[\]]*)
""", re.VERBOSE)

TYPES = ("String", "boolean", "byte", "short", "int", "long", "float", "double", "char", "Uri", "Bundle", "Intent",
         "String[]", "boolean[]", "byte[]", "short[]", "int[]", "long[]", "float[]", "double[]", "char[]", "Intent[]")
TYPE_DEFAULTS = {"String": '"$0"', "char": '"$0"', "Uri": '"$0"', "boolean": "false$0", "long": '"0$0"',
                 "float": "0.0$0", "double": "0.0$0", "Bundle": "{$0}", "Intent": "{$0}"}
INTENT_SNIPPET = ('{\n    "component": ${null},\n    "action": null,\n    "data": null,\n    "flags": 0,\n'
                  '    "categories": [],\n    "extras": {}\n}')
TEXT, NUMBER, LIST, BLOCK = '"$0"', "$0", "[$0]", "{\n    $0\n}"
KEYS = {
    "intent": {"component": TEXT, "package": TEXT, "action": TEXT, "data": TEXT, "mimeType": TEXT, "flags": "0$0",
               "categories": LIST, "extras": BLOCK, "selector": INTENT_SNIPPET,
               "clipData": '{\n    "label": null,\n    "mimeTypes": ["text/plain"],\n    "items": [\n        {"text": "$0"}\n    ]\n}'},
    "clip": {"label": TEXT, "mimeTypes": '["$0"]', "items": '[\n    {"text": "$0"}\n]'},
    "item": {"text": TEXT, "htmlText": TEXT, "uri": TEXT, "intent": INTENT_SNIPPET},
    "entry": {"type": TEXT, "value": NUMBER},
}
PROVIDER_KEYS = {
    "query": ("uri", "projection", "selection", "selectionArgs", "sortOrder", "maxRows", "maxBytes"),
    "getType": ("uri",), "insert": ("uri", "values"), "update": ("uri", "values", "selection", "selectionArgs"),
    "delete": ("uri", "selection", "selectionArgs"), "call": ("uri", "method", "arg", "extras"),
    "openFileDescriptor": ("uri", "maxBytes"),
}
REQUEST_SNIPPETS = {"operation": TEXT, "intent": INTENT_SNIPPET, "receiverPermission": TEXT, "uri": '"content://$0"',
                    "projection": LIST, "selection": TEXT, "selectionArgs": LIST, "sortOrder": TEXT,
                    "values": BLOCK, "method": TEXT, "arg": TEXT, "extras": BLOCK, "maxRows": "100$0",
                    "maxBytes": "65536$0"}

# What each operation needs before it can be saved, written after the operation of a new request.
OPERATION_SKELETONS = {
    **{name: ',\n"intent": {\n    $0\n}' for name in INTENT_OPERATIONS},
    "startActivity": ',\n"intent": {\n    "flags": 268435456$0\n}',
    **{name: ',\n"uri": "content://$0"' for name in PROVIDER_OPERATIONS},
    **{name: ',\n"uri": "content://$0",\n"values": {}' for name in ("insert", "update")},
}


def format_request(request):
    return json.dumps(request, indent=4, ensure_ascii=False)


# ---------------------------------------------------------------- tokens

def tokens(text):
    """Yield (kind, start, end, text). Strings before a colon are keys."""
    found = [(match.lastgroup, match.start(), match.end(), match.group()) for match in TOKEN.finditer(text)]
    for index, (kind, start, end, value) in enumerate(found):
        if kind == "string" and index + 1 < len(found) and found[index + 1][3] == ":":
            kind = "key"
        yield kind, start, end, value


def highlights(text):
    """Per line, (start byte, end byte, name) spans in the form TextArea draws."""
    starts = [0]
    for match in re.finditer("\n", text):
        starts.append(match.end())
    result, line = {}, 0
    for kind, start, end, _ in tokens(text):
        while line + 1 < len(starts) and starts[line + 1] <= start:
            line += 1
        prefix = text[starts[line]:start]
        begin = len(prefix.encode("utf-8"))
        result.setdefault(line, []).append((begin, begin + len(text[start:end].encode("utf-8")), "json." + kind))
    return result


# ---------------------------------------------------------------- context

class Frame:
    def __init__(self, bracket, start):
        self.bracket, self.start = bracket, start
        self.key = None            # Key whose value is being written.
        self.state = "key" if bracket == "{" else "value"
        self.fields = {}           # Keys seen so far; text values are kept for `type` and `operation`.
        self.last_end = start + 1  # Where a missing comma would go.


def _scan(text):
    frames = []
    for kind, start, end, value in tokens(text):
        top = frames[-1] if frames else None
        if value in ("{", "["):
            frames.append(Frame(value, start))
            continue
        if value in ("}", "]"):
            if frames:
                frames.pop()
            if frames:
                frames[-1].state, frames[-1].last_end = "after", end
            continue
        if top is None:
            continue
        if value == ":":
            top.state = "value"
        elif value == ",":
            top.state = "key" if top.bracket == "{" else "value"
        elif top.bracket == "{" and top.state in ("key", "after") and kind in ("string", "key"):
            top.key = _plain(value)
            top.fields.setdefault(top.key, None)
            top.state, top.last_end = "colon", end
        else:
            if top.bracket == "{" and top.key is not None and kind == "string":
                top.fields[top.key] = _plain(value)
            top.state, top.last_end = "after", end
    return frames


def _plain(literal):
    try:
        return json.loads(literal if literal.endswith('"') and len(literal) > 1 else literal + '"')
    except ValueError:
        return literal.strip('"')


def _kind(frames):
    """What the innermost object describes: request, intent, bundle, entry, clip or item."""
    kind = None
    for index, frame in enumerate(frames):
        parent = frames[index - 1] if index else None
        if frame.bracket == "[":
            kind = {"clip:items": "items", "entry:value": "elements"}.get(f"{kind}:{parent.key if parent else ''}")
            if kind == "elements" and (parent.fields.get("type") or "") != "Intent[]":
                kind = None
            continue
        if parent is None:
            kind = "request"
        elif kind in ("items", "elements"):
            kind = "item" if kind == "items" else "intent"
        elif kind == "bundle":
            kind = "entry"
        elif kind == "entry" and parent.key == "value":
            kind = {"Intent": "intent", "Bundle": "bundle"}.get(parent.fields.get("type"))
        elif parent.key in ("intent", "selector") and kind in ("request", "intent", "item"):
            kind = "intent"
        elif parent.key in ("extras", "values") and kind in ("request", "intent"):
            kind = "bundle"
        elif parent.key == "clipData" and kind == "intent":
            kind = "clip"
        else:
            kind = None
    return kind


def context(text, offset):
    """Describe the cursor: what is being typed, where it starts, and which names fit there."""
    before = text[:offset]
    last = None
    for last in tokens(before):
        pass
    if last is not None and last[0] == "string" and last[2] == offset and \
            (len(last[3]) == 1 or not re.search(r'(?<!\\)(?:\\\\)*"$', last[3])):
        word = last[3]  # Inside an open string: all of it is the word, spaces included.
    else:
        match = re.search(r"[A-Za-z_][\w\[\]]*$", before)
        word = match.group() if match else ""
    start = offset - len(word)
    frames = _scan(text[:start])
    top = frames[-1] if frames else None
    result = {"prefix": word.lstrip('"'), "start": start, "quoted": word.startswith('"'), "options": [],
              "comma_at": None, "position": None}
    if top is None:
        return result
    kind = _kind(frames)
    root = frames[0].fields
    if top.bracket == "{" and top.state in ("key", "after"):
        result["position"] = "key"
        if top.state == "after":
            result["comma_at"] = top.last_end
        if kind == "request":
            operation = root.get("operation")
            names = ("operation", "intent", "receiverPermission") if operation in INTENT_OPERATIONS else \
                ("operation", *PROVIDER_KEYS[operation]) if operation in PROVIDER_OPERATIONS else tuple(REQUEST_SNIPPETS)
            options = [(name, f'"{name}": {REQUEST_SNIPPETS[name]}') for name in names]
        elif kind == "bundle":
            options = [(name, f'"$0": {{"type": "{name}", "value": {_entry_value(name)}}}') for name in TYPES]
        else:
            options = [(name, f'"{name}": {snippet}') for name, snippet in KEYS.get(kind, {}).items()]
        result["options"] = [(name, snippet) for name, snippet in options if kind == "bundle" or name not in top.fields]
    elif top.state == "value":
        result["position"] = "value"
        names = ()
        if top.bracket == "{" and top.key == "operation" and kind == "request":
            names = OPERATIONS
        elif top.bracket == "{" and top.key == "type" and kind == "entry":
            names = TYPES
        # In a request that has nothing else yet, choosing the operation also writes what it needs.
        skeleton = names is OPERATIONS and not set(root) - {"operation"} and re.fullmatch(r'"?[ \t]*\n\s*\}\s*', text[offset:])
        result["options"] = [(name, f'"{name}"' + (OPERATION_SKELETONS[name] if skeleton else "$0")) for name in names] or \
            ([] if result["quoted"] else [(name, name + "$0") for name in ("null", "true", "false")])
    return result


def _entry_value(kind):
    """Inside an entry snippet the cursor goes to the key, so the value is only a valid default."""
    if kind.endswith("[]"):
        return "[]"
    return TYPE_DEFAULTS.get(kind, "0$0").replace("$0", "")


def completions(text, offset, always=False):
    """Matching (label, snippet) pairs, best first. Empty unless something was typed or `always`."""
    found = context(text, offset)
    prefix = found["prefix"].casefold()
    if not prefix and not always:
        return found, []
    exact = [option for option in found["options"] if option[0].startswith(found["prefix"])]
    starts = [option for option in found["options"] if option[0].casefold().startswith(prefix) and option not in exact]
    contains = [option for option in found["options"]
                if prefix in option[0].casefold() and option not in exact and option not in starts]
    matches = exact + starts + contains
    if len(matches) == 1 and matches[0][0] == found["prefix"] and found["position"] == "value":
        return found, []  # Already written in full.
    return found, matches


def apply_completion(text, offset, found, snippet):
    """Insert `snippet` over the typed word. Returns (text, cursor offset, selected length).

    `$0` marks where the cursor goes; `${text}` leaves `text` selected so typing replaces it.
    """
    line_start = text.rfind("\n", 0, found["start"]) + 1
    indent = re.match(r"[ \t]*", text[line_start:]).group()
    end = offset
    if found["quoted"]:
        start = found["start"]
        if text[end:end + 1] == '"':
            end += 1  # The closing quote typed by auto-pairing.
    else:
        start = found["start"]
    body = snippet.replace("\n", "\n" + indent)
    selected = 0
    if placeholder := re.search(r"\$\{([^}]*)\}", body):
        cursor, selected = placeholder.start(), len(placeholder.group(1))
        body = body[:cursor] + placeholder.group(1) + body[placeholder.end():]
    else:
        cursor = body.find("$0")
    body = body.replace("$0", "")
    head = text[:start]
    comma = found.get("comma_at")
    if comma is not None and comma <= len(head):
        head = head[:comma] + "," + head[comma:]
        start += 1
    return head + body + text[end:], start + (cursor if cursor >= 0 else len(body)), selected


# ---------------------------------------------------------------- folding

def _pairs(text):
    """(open, close) offsets of every bracket pair, innermost last for a given position."""
    stack, pairs = [], []
    for _, start, end, value in tokens(text):
        if value in ("{", "["):
            stack.append(start)
        elif value in ("}", "]") and stack:
            pairs.append((stack.pop(), end))
    return pairs


def toggle_fold(text, offset, folds):
    """Unfold the marker on the cursor line, or fold the smallest multi-line block around the cursor.

    `folds` maps a marker number to the hidden text and is updated in place.
    Returns (text, cursor offset), or None when there is nothing to do.
    """
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    line_end = len(text) if line_end < 0 else line_end
    markers = list(FOLD.finditer(text, line_start, line_end))
    if markers:
        marker = min(markers, key=lambda match: abs(match.start() - offset))
        number = _number(marker.group(2))
        hidden = folds.pop(number, None)
        if hidden is None:
            return None
        return text[:marker.start()] + hidden + text[marker.end():], marker.start() + 1
    blocks = [(start, end) for start, end in _pairs(text) if "\n" in text[start:end] and text[:start].strip()]
    # A block that opens on this line is the one meant; otherwise the smallest one around the cursor.
    opening = [pair for pair in blocks if line_start <= pair[0] < line_end]
    around = [pair for pair in blocks if pair[0] <= offset <= pair[1]]
    if not opening and not around:
        return None
    start, end = min(opening, key=lambda pair: pair[0]) if opening else max(around, key=lambda pair: pair[0])
    # Never reuse a number that is still written somewhere, e.g. in text pasted from another request.
    written = [_number(match.group(2)) for match in FOLD.finditer(text)]
    number = max([*folds, *written], default=0) + 1
    folds[number] = text[start:end]
    closer = "}" if text[start] == "{" else "]"
    marker = f"{text[start]}⋯{str(number).translate(SUBSCRIPT)}{closer}"
    return text[:start] + marker + text[end:], start


def _number(subscript):
    return int(subscript.translate(str.maketrans("₀₁₂₃₄₅₆₇₈₉", "0123456789")))


def expand(text, folds, _open=()):
    """The full text behind every fold marker, nested ones included."""
    def restore(match):
        number = _number(match.group(2))
        if number not in folds or number in _open:  # Unknown, or a marker inside its own content.
            return match.group()
        return expand(folds[number], folds, (*_open, number))
    return FOLD.sub(restore, text)


def parse(text, folds=None):
    """Read the editor text as a request object. A trailing comma before a closer is forgiven."""
    full = expand(text, folds or {})
    cleaned = []
    for kind, start, end, value in tokens(full):
        if value in ("}", "]") and cleaned and cleaned[-1][1] == ",":
            cleaned.pop()
        cleaned.append((start, value))
    rebuilt, position = [], 0
    kept = {start for start, _ in cleaned}
    for kind, start, end, value in tokens(full):
        rebuilt.append(full[position:start])
        rebuilt.append(value if start in kept else " ")
        position = end
    rebuilt.append(full[position:])
    try:
        value = json.loads("".join(rebuilt))
    except json.JSONDecodeError as error:
        raise ValueError(f"Line {error.lineno}, column {error.colno}: {error.msg}") from None
    if not isinstance(value, dict):
        raise ValueError("A request is a JSON object: { ... }")
    return value
