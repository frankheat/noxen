from textual.widgets import Select


SELECT_EMPTY = getattr(Select, "NULL", getattr(Select, "BLANK"))


def is_select_empty(value) -> bool:
    return value is SELECT_EMPTY
