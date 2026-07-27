"""scoutkit — shared primitives for the Scout AgentOps Kit skill pack.

Every skill in this pack is a deterministic, offline analyzer: it reads
structured evidence from disk, produces findings, and renders canonical
JSON plus human-reviewable Markdown/HTML. Nothing here performs network
I/O, mutates a tenant, or sends a message.
"""

from .automation import describe_schedule
from .findings import Finding, Report, Severity
from .hashing import chain_digest, sha256_bytes, sha256_file, sha256_text
from .io import (
    RESULT_SCHEMA_VERSION,
    append_jsonl,
    iter_text_files,
    read_json,
    read_jsonl,
    read_text,
    write_json,
    write_text,
)
from .render import render_html, render_markdown
from .text import is_negated, mask_prohibitions, prohibition_spans

__all__ = [
    "Finding",
    "Report",
    "Severity",
    "chain_digest",
    "sha256_bytes",
    "sha256_file",
    "sha256_text",
    "RESULT_SCHEMA_VERSION",
    "append_jsonl",
    "iter_text_files",
    "read_json",
    "read_jsonl",
    "read_text",
    "write_json",
    "write_text",
    "render_html",
    "render_markdown",
    "is_negated",
    "mask_prohibitions",
    "prohibition_spans",
    "describe_schedule",
]

__version__ = "1.1.0"
