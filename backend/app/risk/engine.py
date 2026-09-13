"""Explainable baseline cyber-risk engine (Review 1).

This is a transparent rule-based model (NOT machine learning).
Scores are normalized to 0–100 with documented weights.
"""

from __future__ import annotations

from statistics import mean

from sqlalchemy.orm import Session

from app.attack_graph import AttackGraphEngine
from app.core.config import get_settings
from app.core.enums import (
    CRITICALITY_SCORE,
    EXPLOITABILITY_SCORE,
    SEVERITY_SCORE,
    TrustLevel,
    VulnerabilityStatus,
    risk_band_from_score,
)
from app.digital_twin import DigitalTwinService
from app.schemas.digital_twin import TwinAssetNode
from app.schemas.risk import AssetRisk, PathRisk, RiskFactor, RiskOverview

TRUST_EXPOSURE = {
    TrustLevel.UNTRUSTED: 1.0,
    TrustLevel.LOW: 0.8,
    TrustLevel.MEDIUM: 0.55,
    TrustLevel.HIGH: 0.35,
    TrustLevel.FULL: 0.2,
}


def _factor(name: str, value: float, weight: float, detail: str) -> RiskFactor:
    weighted = round(value * weight, 4)
    return RiskFactor(
        name=name,
        value=round(value, 4),
        weight=weight,
        weighted_contribution=weighted,
        contribution=round(weighted * 100, 2),
        detail=detail,
    )


class BaselineRiskEngine:
    """Configurable weighted baseline risk model."""

    MODEL_VERSION = "baseline-v1"

    def __init__(self, db: Session) -> None:
        self.db = db
        self.settings = get_settings()
        self.twin_service = DigitalTwinService(db)
        self.graph_engine = AttackGraphEngine(db)

    def _weights(self) -> dict[str, float]:
        raw = {
            "severity": self.settings.risk_weight_severity,
            "exploitability": self.settings.risk_weight_exploitability,
            "criticality": self.settings.risk_weight_criticality,
            "path": self.settings.risk_weight_path,
        }
        total = sum(raw.values()) or 1.0
        return {k: v / total for k, v in raw.items()}

    def score_asset(self, asset: TwinAssetNode, path_exposure: float = 0.0) -> AssetRisk:
        weights = self._weights()
        open_vulns = [v for v in asset.vulnerabilities if v.status == VulnerabilityStatus.OPEN]

        if open_vulns:
            sev = mean(SEVERITY_SCORE[v.severity] for v in open_vulns)
            exp = mean(EXPLOITABILITY_SCORE[v.exploitability] for v in open_vulns)
            cvss_norm = mean(min(1.0, v.cvss_score / 10.0) for v in open_vulns)
            severity_input = 0.6 * sev + 0.4 * cvss_norm
        else:
            severity_input = 0.05
            exp = 0.05

        criticality_input = CRITICALITY_SCORE[asset.criticality]
        trust_input = TRUST_EXPOSURE.get(asset.trust_level, 0.55)
        # Blend configured path weight with local trust exposure / connectivity proxy.
        path_input = min(1.0, 0.5 * path_exposure + 0.5 * trust_input)

        factors = [
            _factor(
                "severity_cvss",
                severity_input,
                weights["severity"],
                (
                    f"{len(open_vulns)} open synthetic vuln(s); "
                    f"severity/CVSS composite={severity_input:.3f}"
                ),
            ),
            _factor(
                "exploitability",
                exp,
                weights["exploitability"],
                f"Mean exploitability of open findings={exp:.3f}",
            ),
            _factor(
                "criticality",
                criticality_input,
                weights["criticality"],
                f"Asset criticality={asset.criticality.name} ({int(asset.criticality)})",
            ),
            _factor(
                "path_exposure_trust",
                path_input,
                weights["path"],
                (
                    f"Trust={asset.trust_level.value}; path_exposure={path_exposure:.3f}; "
                    f"combined={path_input:.3f}"
                ),
            ),
        ]
        score = round(min(100.0, sum(f.contribution for f in factors)), 2)
        band = risk_band_from_score(score)
        explanation = (
            f"{asset.asset_name} baseline risk={score} ({band.value}) using {self.MODEL_VERSION}. "
            + "; ".join(f"{f.name} contributes {f.contribution:.1f} pts" for f in factors)
        )
        return AssetRisk(
            asset_id=asset.asset_id,
            asset_name=asset.asset_name,
            risk_score=score,
            risk_band=band,
            factors=factors,
            explanation=explanation,
        )

    def score_path(self, path, asset_scores: dict[str, AssetRisk]) -> PathRisk:
        weights = self._weights()
        node_scores = [asset_scores[aid].risk_score / 100.0 for aid in path.asset_ids if aid in asset_scores]
        avg_node = mean(node_scores) if node_scores else 0.2
        # Shorter paths to critical targets are riskier analytically.
        length = max(1, path.length)
        length_factor = max(0.25, min(1.0, 1.15 - 0.08 * (length - 2)))
        stage_factor = min(1.0, path.stage_count / 6.0)
        vuln_factor = min(1.0, len(path.vulnerabilities_on_path) / 4.0)

        # Re-balance path-specific blend while remaining explainable.
        factors = [
            _factor(
                "avg_node_risk",
                avg_node,
                0.45,
                "Mean baseline risk of assets on the path",
            ),
            _factor(
                "path_length_pressure",
                length_factor,
                0.2,
                f"length={length}; shorter analytical paths score higher",
            ),
            _factor(
                "stage_depth",
                stage_factor,
                0.15,
                f"stage_count={path.stage_count}",
            ),
            _factor(
                "transition_vulns",
                vuln_factor,
                0.2,
                f"synthetic vulns on transitions={path.vulnerabilities_on_path}",
            ),
        ]
        # Keep path weights visible alongside global config note
        _ = weights
        score = round(min(100.0, sum(f.contribution for f in factors)), 2)
        band = risk_band_from_score(score)
        display = " → ".join(h.asset_name for h in path.hops)
        explanation = (
            f"Path risk={score} ({band.value}). {path.explanation} "
            + "Contributors: "
            + ", ".join(f"{f.name}={f.contribution:.1f}" for f in factors)
        )
        return PathRisk(
            path_id=path.path_id,
            source_name=path.source_name,
            target_name=path.target_name,
            path_display=display,
            stage_count=path.stage_count,
            risk_score=score,
            risk_band=band,
            factors=factors,
            explanation=explanation,
            scenario_label=path.scenario_label,
        )

    def assess_assets(self) -> list[AssetRisk]:
        twin = self.twin_service.build_snapshot()
        paths = self.graph_engine.discover_paths(max_paths=40).paths
        exposure: dict[str, int] = {a.asset_id: 0 for a in twin.assets}
        for path in paths:
            for aid in path.asset_ids:
                exposure[aid] = exposure.get(aid, 0) + 1
        max_exp = max(exposure.values()) if exposure else 1
        scored = [
            self.score_asset(asset, path_exposure=(exposure.get(asset.asset_id, 0) / max_exp))
            for asset in twin.assets
        ]
        scored.sort(key=lambda a: a.risk_score, reverse=True)
        return scored

    def assess_paths(self) -> list[PathRisk]:
        twin = self.twin_service.build_snapshot()
        raw_paths = self.graph_engine.discover_paths(max_paths=40).paths
        exposure: dict[str, int] = {a.asset_id: 0 for a in twin.assets}
        for path in raw_paths:
            for aid in path.asset_ids:
                exposure[aid] = exposure.get(aid, 0) + 1
        max_exp = max(exposure.values()) if exposure else 1
        asset_scores = {
            asset.asset_id: self.score_asset(
                asset, path_exposure=(exposure.get(asset.asset_id, 0) / max_exp)
            )
            for asset in twin.assets
        }
        scored = [self.score_path(p, asset_scores) for p in raw_paths]
        scored.sort(key=lambda p: p.risk_score, reverse=True)
        return scored

    def overview(self) -> RiskOverview:
        twin = self.twin_service.build_snapshot()
        raw_paths = self.graph_engine.discover_paths(max_paths=40).paths
        exposure: dict[str, int] = {a.asset_id: 0 for a in twin.assets}
        for path in raw_paths:
            for aid in path.asset_ids:
                exposure[aid] = exposure.get(aid, 0) + 1
        max_exp = max(exposure.values()) if exposure else 1

        assets = [
            self.score_asset(asset, path_exposure=(exposure.get(asset.asset_id, 0) / max_exp))
            for asset in twin.assets
        ]
        assets.sort(key=lambda a: a.risk_score, reverse=True)
        asset_map = {a.asset_id: a for a in assets}
        paths = [self.score_path(p, asset_map) for p in raw_paths]
        paths.sort(key=lambda p: p.risk_score, reverse=True)

        overall = round(mean(a.risk_score for a in assets), 2) if assets else 0.0
        band = risk_band_from_score(overall)
        distribution = {
            "VERY_LOW": 0,
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        }
        for a in assets:
            distribution[a.risk_band.value] += 1

        high_assets = [a for a in assets if a.risk_band.value in {"HIGH", "CRITICAL"}]
        high_paths = [p for p in paths if p.risk_band.value in {"HIGH", "CRITICAL"}]

        weights = self._weights()
        factors_summary = [
            _factor(name, 1.0, weight, f"Configured normalized weight for {name}")
            for name, weight in weights.items()
        ]

        explanation = (
            f"Overall baseline risk={overall} ({band.value}) as mean of {len(assets)} asset scores "
            f"under {self.MODEL_VERSION}. This is an explainable rule-based baseline, not ML prediction."
        )
        return RiskOverview(
            overall_risk_score=overall,
            overall_risk_band=band,
            model_version=self.MODEL_VERSION,
            asset_count=twin.asset_count,
            assessed_assets=len(assets),
            path_count=len(paths),
            high_or_critical_assets=len(high_assets),
            high_or_critical_paths=len(high_paths),
            factors_summary=factors_summary,
            explanation=explanation,
            high_risk_assets=high_assets[:8],
            high_risk_paths=high_paths[:8],
            distribution=distribution,
            notes=[
                "Baseline only — Predictive Cyber Risk Forecasting is deferred to Review 3.",
                "Weights are configurable via environment variables.",
                "All vulnerability inputs are synthetic (SYN-* identifiers).",
            ],
        )
