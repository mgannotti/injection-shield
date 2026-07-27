"""Pytest configuration for Injection Shield.

Puts the vendored shared library and the engine directory on ``sys.path`` so tests
can import by module name, and pins the clock so artifacts are byte-reproducible.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
FROZEN_NOW = "2026-01-01T00:00:00Z"

sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "scripts"))

os.environ.setdefault("SCOUTKIT_NOW", FROZEN_NOW)


@pytest.fixture(scope="session")
def pack_root() -> Path:
    return ROOT


@pytest.fixture
def template(pack_root: Path):
    """Resolve a bundled example file. The slug argument is accepted and ignored:
    a standalone repo holds exactly one skill, so templates live at ``templates/``."""
    def _resolve(slug: str, filename: str) -> Path:
        path = pack_root / "templates" / filename
        assert path.is_file(), f"missing bundled template: {path}"
        return path
    return _resolve


@pytest.fixture
def write(tmp_path: Path):
    """Write a temp file and return its path."""
    def _write(name: str, content: str) -> Path:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path
    return _write
