"""Keep the single-line extra editor from displaying or dropping control data."""

import json
import unicodedata

from textual import events
from textual.widgets import Input


def needs_value_preview(value: str) -> bool:
    """Line breaks, controls, surrogates and bidi overrides need an explicit preview."""
    return any(
        unicodedata.category(char) in {"Cc", "Cs", "Zl", "Zp"}
        or unicodedata.bidirectional(char) in {
            "LRE", "LRO", "RLE", "RLO", "PDF", "LRI", "RLI", "FSI", "PDI",
        }
        for char in value
    )


def extra_value_preview(value: str) -> str:
    """Return a safe, unambiguous JSON string representation, including its quotes."""
    encoded = json.dumps(value, ensure_ascii=False)
    return "".join(
        json.dumps(char, ensure_ascii=True)[1:-1] if needs_value_preview(char) else char
        for char in encoded
    )


class ExtraValueInput(Input):
    """Reject unsupported paste atomically, for both terminal and local clipboard."""

    def _paste_value(self, text: str) -> None:
        if self.disabled or not text:
            return
        if needs_value_preview(text):
            self.notify(
                "Line breaks or control characters cannot be edited inline. Nothing was inserted.",
                title="Value not inserted",
                severity="error",
            )
            return
        self.replace(text, *self.selection)

    def _on_paste(self, event: events.Paste) -> None:
        event.prevent_default()
        event.stop()
        self._paste_value(event.text)

    def action_paste(self) -> None:
        self._paste_value(self.app.clipboard)
