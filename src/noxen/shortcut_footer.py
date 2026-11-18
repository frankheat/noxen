"""Keep application shortcuts in their declared order, ahead of local shortcuts."""

from textual.widgets import Footer

try:
    from textual.compose import compose
except ImportError:  # Older Textual footers yield a flat list of keys.
    compose = None


class ShortcutFooter(Footer):
    def compose(self):
        # Textual orders visible bindings by focus ancestry, so a focused
        # editor can move its shortcuts ahead of Quit. Reorder only the
        # rendered keys: Textual still resolves, enables and dispatches them.
        app_order = {binding.key: index for index, binding in enumerate(self.app.BINDINGS)}
        local = len(self.app.BINDINGS)
        original = super().compose()
        widgets = original if compose is None else compose(self, original)
        yield from sorted(widgets, key=lambda widget: app_order.get(getattr(widget, "key", None), local))
