"""Prohibition-aware text handling.

Automation prompts are dense with safety language — "never send", "do NOT
archive", "NEVER DO: auto-delete". A detector that pattern-matches verbs without
reading the surrounding polarity converts each of those guarantees into a
reported capability, so the safest prompts generate the loudest false alarms.

This module locates the regions of a text that are under a prohibition, so
callers can match against the *commanded* text only.

    spans = prohibition_spans(prompt)
    if not is_negated(spans, match.start()):
        ...                       # a real instruction
    positive = mask_prohibitions(prompt)   # offsets preserved

Deterministic and dependency-free, like everything else in the pack.
"""

from __future__ import annotations

import re

__all__ = ["prohibition_spans", "is_negated", "mask_prohibitions", "PROHIBITION_MARKER"]

# Markers that flip the polarity of whatever follows them in the same clause.
PROHIBITION_MARKER = re.compile(
    r"\b(?:never|do\s+not|does\s+not|doesn'?t|don'?t|must\s+not|mustn'?t|shall\s+not|"
    r"should\s+not|shouldn'?t|may\s+not|cannot|can'?t|won'?t|will\s+not|no\s+longer|"
    r"avoid|refrain\s+from|without|rather\s+than|instead\s+of|under\s+no\s+circumstances)\b",
    re.IGNORECASE,
)

# A prohibition normally reaches the end of its clause.
_CLAUSE_END = re.compile(r"[.;!?\n]")
# "NEVER DO:" / "Never:" introduces a list, which runs to the end of the block.
_INTRODUCES_LIST = re.compile(r"^[^\n:]{0,40}:\s*$|^[^\n:]{0,40}:\s*\n", re.IGNORECASE)
_BLOCK_END = re.compile(r"\n\s*\n")
# Polarity resets on an explicit contrast: "never send; instead, draft a reply".
_POLARITY_RESET = re.compile(
    r"\b(?:instead|rather|but\s+do|however|except\s+that|otherwise)\b", re.IGNORECASE
)


def _span_end(text: str, start: int) -> int:
    """Where the prohibition beginning at ``start`` stops applying."""
    tail = text[start:]

    # "NEVER DO:" style heading — the whole following block is forbidden.
    heading = _INTRODUCES_LIST.match(tail)
    if heading:
        block = _BLOCK_END.search(text, start + heading.end())
        return block.start() if block else len(text)

    reset = _POLARITY_RESET.search(tail)
    clause = _CLAUSE_END.search(tail)
    candidates = [m.start() for m in (reset, clause) if m is not None]
    return start + min(candidates) if candidates else len(text)


def prohibition_spans(text: str) -> list[tuple[int, int]]:
    """Return ``[(start, end)]`` character ranges that are under a prohibition.

    Overlapping prohibitions are merged, so a clause carrying several markers
    ("do NOT send any outbound messages, do NOT touch any folder") yields one span.
    """
    if not text:
        return []
    spans: list[tuple[int, int]] = []
    for marker in PROHIBITION_MARKER.finditer(text):
        spans.append((marker.start(), _span_end(text, marker.start())))
    if not spans:
        return []
    spans.sort()
    merged = [spans[0]]
    for start, end in spans[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def is_negated(spans: list[tuple[int, int]], position: int) -> bool:
    """True when ``position`` falls inside a prohibited range."""
    return any(start <= position < end for start, end in spans)


def mask_prohibitions(text: str, fill: str = " ") -> str:
    """Blank out every prohibited range, preserving length so offsets still line up.

    The result contains only what the automation was told *to* do, which is the
    text a capability or intent detector should be reading.
    """
    spans = prohibition_spans(text)
    if not spans:
        return text
    chars = list(text)
    for start, end in spans:
        for i in range(start, min(end, len(chars))):
            if chars[i] != "\n":
                chars[i] = fill
    return "".join(chars)
