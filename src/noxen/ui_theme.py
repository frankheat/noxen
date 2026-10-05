from dataclasses import dataclass
import re

from textual.theme import Theme


@dataclass(frozen=True)
class SemanticColors:
    success: str
    warning: str
    error: str
    info: str
    muted: str
    brand_start: str
    brand_end: str


DARK_COLORS = SemanticColors(
    success="#32B77A",
    warning="#E7BE42",
    error="#FFB3B8",
    info="#65B8E8",
    muted="#9AA8A3",
    brand_start="#D967A5",
    brand_end="#32B77A",
)

LIGHT_COLORS = SemanticColors(
    success="#126B49",
    warning="#684900",
    error="#A52F45",
    info="#176A92",
    muted="#56645E",
    brand_start="#8B2E63",
    brand_end="#126B49",
)


def semantic_colors(dark: bool) -> SemanticColors:
    return DARK_COLORS if dark else LIGHT_COLORS


def themed_markup(markup: str, dark: bool) -> str:
    """Resolve semantic Rich colors for the active background."""
    colors = semantic_colors(dark)
    replacements = {
        "#26a368": colors.success,
        "#f2c94c": colors.warning,
        "#ffb1b1": colors.error,
        "#58c4ff": colors.info,
        "red": colors.error,
        "yellow": colors.warning,
        "green": colors.success,
    }

    def replace_tag(match: re.Match) -> str:
        content = match.group(1)
        prefix = "/" if content.startswith("/") else ""
        styles = content.removeprefix("/").split()
        resolved = [replacements.get(style.lower(), style) for style in styles]
        return f"[{prefix}{' '.join(resolved)}]"

    return re.sub(r"(?<!\\)\[([^\]]+)\]", replace_tag, markup)


NOXEN_DARK_THEME = Theme(
    name="noxen-dark",
    primary="#32B77A",
    secondary="#65B8E8",
    warning=DARK_COLORS.warning,
    error="#D86470",
    success=DARK_COLORS.success,
    accent="#D5A934",
    foreground="#E8EFEC",
    background="#0E1412",
    surface="#131C19",
    panel="#1B2723",
    boost="#24352F",
    dark=True,
    variables={
        "content-background": "#0E1412",
        "footer-background": "#1B2723",
        "footer-foreground": "#C9D5D0",
        "footer-key-foreground": DARK_COLORS.warning,
        "input-selection-background": "#A23F76 55%",
        "button-color-foreground": "#07120D",
    },
)


NOXEN_LIGHT_THEME = Theme(
    name="noxen-light",
    primary=LIGHT_COLORS.success,
    secondary=LIGHT_COLORS.info,
    warning=LIGHT_COLORS.warning,
    error=LIGHT_COLORS.error,
    success=LIGHT_COLORS.success,
    accent="#6B5708",
    foreground="#17211D",
    background="#F3F6F4",
    surface="#FFFFFF",
    panel="#E7ECE9",
    boost="#DCE5E1",
    dark=False,
    variables={
        "content-background": "#FFFFFF",
        "footer-background": "#E0E6E3",
        "footer-foreground": "#26332E",
        "footer-key-foreground": LIGHT_COLORS.success,
        "input-selection-background": "#8B2E63 35%",
        "button-color-foreground": "#FFFFFF",
    },
)


def register_noxen_themes(app) -> None:
    """Replace Textual's generic light/dark themes with noxen's paired palettes."""
    app.register_theme(NOXEN_DARK_THEME)
    app.register_theme(NOXEN_LIGHT_THEME)
