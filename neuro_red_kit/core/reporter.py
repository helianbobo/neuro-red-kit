from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ReportEngine:
    """Builds human-readable reports from results."""

    def render(self, results: Any) -> str:
        return f"NeuroRedKit report (scaffold)\nResults: {results!r}\n"
