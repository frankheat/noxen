from textual.widgets import Select


SELECT_EMPTY = getattr(Select, "NULL", getattr(Select, "BLANK"))


def is_select_empty(value) -> bool:
    return value is SELECT_EMPTY


def set_button_label(button, label) -> None:
    """Change a button's label and its width with it: Textual only repaints a new label."""
    if str(button.label) != str(label):
        button.label = label
        button.refresh(layout=True)
