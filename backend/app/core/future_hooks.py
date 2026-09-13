"""Future Review interfaces — NOT implemented in Review 1.

These stubs document extension points for Reviews 3–5 without claiming
completed predictive ML, SDN response, or evaluation capabilities.
"""

from __future__ import annotations

from typing import Protocol


class PredictiveRiskForecaster(Protocol):
    """Review 3 — ML-based predictive cyber-risk forecasting (NOT IMPLEMENTED)."""

    def forecast(self, *args, **kwargs):  # pragma: no cover
        raise NotImplementedError("Predictive forecasting is deferred to Review 3")


class NaturalLanguageSecurityAnalyst(Protocol):
    """Review 3 — NL security analyst (NOT IMPLEMENTED)."""

    def analyze(self, *args, **kwargs):  # pragma: no cover
        raise NotImplementedError("NL analyst is deferred to Review 3")


class SDNResponseController(Protocol):
    """Review 4 — SDN mitigation / isolation (NOT IMPLEMENTED)."""

    def isolate(self, *args, **kwargs):  # pragma: no cover
        raise NotImplementedError("SDN response is deferred to Review 4")


class ExperimentalEvaluator(Protocol):
    """Review 5 — comparative evaluation / benchmarking (NOT IMPLEMENTED)."""

    def evaluate(self, *args, **kwargs):  # pragma: no cover
        raise NotImplementedError("Evaluation suite is deferred to Review 5")


FUTURE_SCOPE_NOTES = [
    "Review 2: advanced attack simulation / propagation",
    "Review 3: predictive ML risk + natural-language analyst",
    "Review 4: SDN-based automated response",
    "Review 5: experimental evaluation and benchmarking",
]
