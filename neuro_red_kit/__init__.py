"""
NeuroRedKit - A Red Teaming Toolkit for Neural-Agent Hybrid Systems

Version: 0.1.0-alpha
"""

__version__ = "0.1.0-alpha"
__author__ = "Chao Liu (Sol)"
__email__ = "neuro-red-kit@proton.me"

from .core.engine import RedTeamEngine
from .core.evaluator import EvaluationEngine
from .core.reporter import ReportEngine

__all__ = [
    "RedTeamEngine",
    "EvaluationEngine",
    "ReportEngine",
]
