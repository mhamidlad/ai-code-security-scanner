"""JSON reporter — stable schema for CI integration."""

from __future__ import annotations

import json

from ..models import ScanResult


def render_json(result: ScanResult, indent: int = 2) -> str:
    """Render a scan result as a JSON string."""
    return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False)
