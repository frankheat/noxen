"""Readable Java stack frames, with lossless fallback for unknown formats."""
import re

_PRIMITIVES = {
    "Z": "boolean", "B": "byte", "C": "char", "S": "short", "I": "int",
    "J": "long", "F": "float", "D": "double", "V": "void",
}
_FRAME = re.compile(r"^L([^;]+);,([^,]+),\(([^)]*)\)(.+)$")


def _type(descriptor, offset, allow_void=False):
    start = offset
    while offset < len(descriptor) and descriptor[offset] == "[":
        offset += 1
    dimensions = offset - start
    if offset == len(descriptor):
        raise ValueError("Missing type")
    token = descriptor[offset]
    if token == "L":
        end = descriptor.index(";", offset)
        name = descriptor[offset + 1:end].replace("/", ".")
        if not name:
            raise ValueError("Empty class")
        offset = end + 1
    else:
        name = _PRIMITIVES[token]
        if token == "V" and (not allow_void or dimensions):
            raise ValueError("Invalid void type")
        offset += 1
    return name + "[]" * dimensions, offset


def format_stack_frame(frame):
    """Convert Frida's JVM signature to class.method(Java argument types)."""
    if not isinstance(frame, str):
        return str(frame)
    match = _FRAME.fullmatch(frame.strip())
    if not match:
        return frame
    clazz, method, arguments, result = match.groups()
    try:
        _, end = _type(result, 0, allow_void=True)
        if end != len(result):
            return frame
        types = []
        offset = 0
        while offset < len(arguments):
            name, offset = _type(arguments, offset)
            types.append(name)
    except (ValueError, KeyError, IndexError):
        return frame
    return f"{clazz.replace('/', '.')}.{method}({', '.join(types)})"
