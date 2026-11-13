"""Text an admin is asked to approve must read the way it is saved: no control, zero-width or
direction-override characters that would make the diff differ from what is stored and run."""

# Printable but invisible: fillers, a blank braille cell, the combining grapheme joiner, variation selectors.
INVISIBLE = {0x034F, 0x115F, 0x1160, 0x2800, 0x3164, 0xFFA0, *range(0xFE00, 0xFE10), *range(0xE0100, 0xE01F0)}


def bad_char(value: str) -> str | None:
    """The first character that must not be in approved text (newlines and tabs are fine), or None."""
    return next((c for c in value if (not c.isprintable() and c not in "\n\t") or ord(c) in INVISIBLE), None)
