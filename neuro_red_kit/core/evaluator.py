from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class EvaluationEngine:
    """Evaluates attack outcomes.

    Future: rule-based scoring + LLM-as-judge + policy checks.
    """

    def evaluate(self, artifact: Any) -> dict[str, Any]:
        return {"verdict": "unknown", "artifact_type": type(artifact).__name__}
