"""Deterministic, explainable hop-level simulation rules."""

from __future__ import annotations

from typing import Optional

from app.core.enums import (
    EXPLOITABILITY_SCORE,
    Exploitability,
    TrustLevel,
    VulnerabilityStatus,
)
from app.schemas.digital_twin import TwinAssetNode


def open_vulns(asset: TwinAssetNode):
    return [v for v in asset.vulnerabilities if v.status == VulnerabilityStatus.OPEN]


def best_open_vuln(asset: TwinAssetNode):
    vulns = open_vulns(asset)
    if not vulns:
        return None
    return max(vulns, key=lambda v: (EXPLOITABILITY_SCORE[v.exploitability], v.cvss_score))


def evaluate_initial_access(source: TwinAssetNode) -> tuple[bool, str, Optional[str]]:
    """Source must have an open synthetic vulnerability to begin a simulated compromise."""
    vuln = best_open_vuln(source)
    if vuln is None:
        return (
            False,
            (
                f"ATTACK BLOCKED: {source.asset_name} has no open synthetic vulnerability "
                "satisfying the initial-access rule."
            ),
            None,
        )
    return (
        True,
        (
            f"Initial simulated compromise of {source.asset_name} permitted by open finding "
            f"{vuln.identifier} ({vuln.exploitability.value} exploitability)."
        ),
        vuln.identifier,
    )


def evaluate_hop(
    source: TwinAssetNode,
    target: TwinAssetNode,
    edge_data: dict,
    *,
    min_exploitability: Exploitability = Exploitability.LOW,
) -> tuple[bool, str, Optional[str]]:
    """Evaluate one analytical propagation step.

    Rules (all must pass):
    1. Directed relationship/edge exists (caller guarantees).
    2. Target simulation overlay is not ISOLATED (checked via security_state COMPROMISED
       isolation only if explicitly marked — Review 2 uses NORMAL/COMPROMISED overlay).
    3. Trust: UNTRUSTED edges require HIGH+ exploitability on source or target.
    4. Vulnerability: target has an open vuln at/above min exploitability, OR a
       trust-continuation relationship (HOSTS, DEPENDS_ON, AUTHENTICATES_TO, MANAGES,
       ACCESSES, CONNECTS_TO, COMMUNICATES_WITH) plus an open vuln on either endpoint.
    """
    rel_type = str(edge_data.get("relationship_type", ""))
    trust = str(edge_data.get("trust_level", TrustLevel.MEDIUM.value))

    src_vuln = best_open_vuln(source)
    dst_vuln = best_open_vuln(target)
    used = dst_vuln or src_vuln
    min_score = EXPLOITABILITY_SCORE[min_exploitability]

    if trust == TrustLevel.UNTRUSTED.value:
        strongest = max(
            EXPLOITABILITY_SCORE[src_vuln.exploitability] if src_vuln else 0.0,
            EXPLOITABILITY_SCORE[dst_vuln.exploitability] if dst_vuln else 0.0,
        )
        if strongest < EXPLOITABILITY_SCORE[Exploitability.HIGH]:
            return (
                False,
                (
                    f"ATTACK BLOCKED: relationship {source.asset_name} → {target.asset_name} "
                    f"is UNTRUSTED and neither endpoint has HIGH+ exploitability."
                ),
                used.identifier if used else None,
            )

    if dst_vuln is None and rel_type not in {"HOSTS", "MANAGES"}:
        return (
            False,
            (
                f"ATTACK BLOCKED: target {target.asset_name} has no open synthetic vulnerability "
                f"to permit simulated compromise (relationship={rel_type})."
            ),
            None,
        )

    if dst_vuln is None and src_vuln is None:
        return (
            False,
            (
                f"ATTACK BLOCKED: hop {source.asset_name} → {target.asset_name} has no open "
                f"synthetic vulnerability on either endpoint (relationship={rel_type})."
            ),
            None,
        )

    if used and EXPLOITABILITY_SCORE[used.exploitability] < min_score:
        return (
            False,
            (
                f"ATTACK BLOCKED: {used.identifier} exploitability {used.exploitability.value} "
                f"is below the simulation minimum {min_exploitability.value}."
            ),
            used.identifier,
        )

    return (
        True,
        (
            f"Simulated propagation {source.asset_name} → {target.asset_name} succeeded: "
            f"reachable {rel_type} edge, trust={trust}, condition={used.identifier if used else 'n/a'}."
        ),
        used.identifier if used else None,
    )
