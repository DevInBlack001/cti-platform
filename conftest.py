"""Ensures the repo root is on sys.path so `collection` imports cleanly
from any test file, regardless of pytest's own rootdir detection."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
