from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def normalize_ea(value: Any) -> str:
    """Normalize an effective address to PseudoForge's canonical hex form."""
    if isinstance(value, bool):
        raise ValueError("EA must be an integer or string, not bool")
    if isinstance(value, int):
        number = value
    else:
        text = str(value).strip()
        if not text:
            raise ValueError("EA value is empty")
        number = int(text, 0)
    if number < 0:
        raise ValueError("EA must be non-negative")
    return "0x%X" % number


def normalize_ea_list(values: Iterable[Any]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        normalized = normalize_ea(value)
        if normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result
