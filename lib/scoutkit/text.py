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

__all__ = [
    "prohibition_spans",
    "is_negated",
    "mask_prohibitions",
    "PROHIBITION_MARKER",
    "placeholder_roles",
    "unresolved_placeholders",
    "significant_tokens",
    "is_scoped_prohibition",
    "prohibition_scope",
]

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


# --- placeholder roles -----------------------------------------------------
#
# A prompt is full of angle-bracket tokens, and they play two completely
# different roles. Some describe the *shape of the output* and the agent fills
# them at run time — "dgm-<slug>-<YYYY-MM-DD>.png". Others are *unresolved
# inputs* that a human was supposed to substitute before scheduling, and a
# scheduled run has nobody to ask. Only the second kind is a defect.
#
# Angle-bracket tokens in prompts are overwhelmingly format tokens, so that is
# the default; a token is only reported as an unresolved input on positive
# evidence.

PLACEHOLDER = re.compile(
    r"\$\{[^}]{1,60}\}"                 # ${var} — interpolation expects a caller
    r"|<[A-Za-z][A-Za-z0-9_ -]{0,40}>"  # <token>
    r"|\[\[[^\]]{1,60}\]\]"             # [[wiki-style]]
    r"|\b(?:TODO|TBD|XXX|FIXME)\b"      # explicit incompleteness markers
)
_ALWAYS_INPUT = re.compile(r"^(?:\$\{|\[\[)|^(?:TODO|TBD|XXX|FIXME)$", re.IGNORECASE)
# Date/time shapes are format tokens by construction.
_DATE_SHAPE = re.compile(r"^<[YMDHhms][YMDHhms:/. _-]*>$")
# A token welded into a larger literal is part of a filename or path pattern.
_LITERAL_NEIGHBOUR = re.compile(r"[\w./\\-]")
# Names that denote something only a human can supply.
_NEEDS_A_HUMAN = frozenset({
    "recipient", "recipients", "email", "address", "to", "cc", "bcc", "name",
    "password", "secret", "token", "key", "apikey", "api_key", "url", "endpoint",
    "tenant", "account", "customer", "client", "user",
})
# An explicit instruction to substitute makes a token an input regardless of shape.
_SUBSTITUTE_CUE = re.compile(
    r"\b(?:replace|substitute|fill\s+in|provide|supply|set|specify|enter)\b[^.\n]{0,40}$",
    re.IGNORECASE,
)


def _placeholder_role(token: str, text: str, start: int) -> str:
    if _ALWAYS_INPUT.match(token):
        return "input"
    if _DATE_SHAPE.match(token):
        return "format"

    before = text[start - 1] if start > 0 else " "
    after = text[start + len(token)] if start + len(token) < len(text) else " "
    if _LITERAL_NEIGHBOUR.match(before) or _LITERAL_NEIGHBOUR.match(after):
        return "format"

    line_start = text.rfind("\n", 0, start) + 1
    if _SUBSTITUTE_CUE.search(text[line_start:start]):
        return "input"

    bare = token.strip("<>").strip().lower().replace(" ", "_")
    if bare in _NEEDS_A_HUMAN:
        return "input"
    return "format"


def placeholder_roles(text: str) -> list[tuple[str, str]]:
    """Return ``[(token, role)]`` where role is ``"input"`` or ``"format"``."""
    seen: dict[str, str] = {}
    for m in PLACEHOLDER.finditer(text or ""):
        token = m.group(0)
        if token not in seen:
            seen[token] = _placeholder_role(token, text, m.start())
    return sorted(seen.items())


def unresolved_placeholders(text: str) -> list[str]:
    """Only the tokens a human still has to resolve before a run can succeed."""
    return [tok for tok, role in placeholder_roles(text) if role == "input"]


# --- prohibition scope -----------------------------------------------------

_STOPWORDS = frozenset({
    "the", "a", "an", "any", "all", "and", "or", "of", "to", "in", "into", "on",
    "for", "with", "without", "from", "at", "by", "it", "its", "this", "that",
    "these", "those", "them", "they", "you", "your", "do", "does", "not", "never",
    "must", "should", "shall", "may", "can", "will", "would", "anything", "else",
})


def significant_tokens(text: str) -> set[str]:
    """Content words, lowercased — the words that carry the meaning of a clause."""
    return {w for w in re.findall(r"[a-z][a-z0-9'-]{2,}", (text or "").lower())
            if w not in _STOPWORDS}


def prohibition_scope(constraint: str, verb_pattern: str) -> set[str]:
    """The subject matter a prohibition protects: content words *after* its verb.

    The verb is excluded deliberately. "Never write X" and "write Y" always share the
    word "write", so counting it would make every prohibition overlap every action of
    the same kind and defeat the comparison entirely.
    """
    match = re.search(verb_pattern, constraint or "", flags=re.IGNORECASE)
    if not match:
        return set()
    return significant_tokens(constraint[match.end():])


def is_scoped_prohibition(constraint: str, verb_pattern: str) -> bool:
    """True when a prohibition names *what* is forbidden, not just the action.

    "Never send" is unconditional: any send contradicts it. "Never write raw email
    content into MEMORY" is scoped — it forbids one kind of write to one target, so
    a plan that writes something else does not necessarily contradict it. The two
    deserve different confidence, and conflating them is what makes a contradiction
    list look uniformly alarming.
    """
    return len(prohibition_scope(constraint, verb_pattern)) >= 2
