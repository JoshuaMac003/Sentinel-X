"""End-to-end Review 1 verification against a running or in-process API."""

from __future__ import annotations

import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from fastapi.testclient import TestClient

from app.main import create_app
from seed.run_seed import run_seed
from seed.smart_hospital_data import (
    A,
    EXPECTED_ASSET_COUNT,
    EXPECTED_RELATIONSHIP_COUNT,
    EXPECTED_VULNERABILITY_COUNT,
)


def main() -> None:
    run_seed(reset=True)
    client = TestClient(create_app())

    health = client.get("/api/health").json()
    assert health["status"] == "ok", health

    assets = client.get("/api/assets").json()
    rels = client.get("/api/relationships").json()
    vulns = client.get("/api/vulnerabilities").json()
    assert len(assets) == EXPECTED_ASSET_COUNT
    assert len(rels) == EXPECTED_RELATIONSHIP_COUNT
    assert len(vulns) == EXPECTED_VULNERABILITY_COUNT
    assert all(v["identifier"].startswith("SYN-") for v in vulns)

    twin = client.get("/api/digital-twin").json()
    assert twin["asset_count"] == EXPECTED_ASSET_COUNT
    assert twin["relationship_count"] == EXPECTED_RELATIONSHIP_COUNT

    # Twin reflects DB mutations
    aid = twin["assets"][0]["asset_id"]
    client.put(f"/api/assets/{aid}", json={"description": "e2e-mutated"})
    twin2 = client.get("/api/digital-twin").json()
    assert any(a["asset_id"] == aid and a.get("description") == "e2e-mutated" for a in twin2["assets"])

    graph = client.get("/api/attack-graph").json()
    assert graph["node_count"] == EXPECTED_ASSET_COUNT
    assert graph["edge_count"] == EXPECTED_RELATIONSHIP_COUNT

    paths = client.get("/api/attack-paths").json()
    assert paths["path_count"] > 0
    labels = [p.get("scenario_label") or "" for p in paths["paths"]]
    assert any("Scenario A" in x for x in labels)
    assert any("Scenario B" in x for x in labels)
    assert any("Scenario C" in x for x in labels)

    # Scenario C long path through Auth must be discoverable
    scen_c = client.get(
        "/api/attack-paths",
        params={
            "source_asset_id": A["doctor"],
            "target_asset_id": A["patient_db"],
            "max_paths": 50,
            "max_length": 8,
        },
    ).json()
    assert scen_c["path_count"] >= 1
    namesets = [" → ".join(h["asset_name"] for h in p["hops"]) for p in scen_c["paths"]]
    assert any(
        "Doctor" in s
        and "Doctor Portal" in s
        and "Authentication Service" in s
        and "Cloud Application Server" in s
        and "Patient Database" in s
        for s in namesets
    ), namesets[:10]

    # Scenario A subsequence
    scen_a = client.get(
        "/api/attack-paths",
        params={
            "source_asset_id": A["patient_monitor"],
            "target_asset_id": A["cloud_app_server"],
        },
    ).json()
    assert scen_a["path_count"] >= 1
    assert any("IoT Gateway" in " → ".join(h["asset_name"] for h in p["hops"]) for p in scen_a["paths"])

    risk = client.get("/api/risk/overview").json()
    assert 0 <= risk["overall_risk_score"] <= 100
    assert risk["factors_summary"]
    assert "rule-based" in risk["explanation"].lower() or "not ml" in risk["explanation"].lower()

    # Convenience alias
    risk_alias = client.get("/api/risk").json()
    assert risk_alias["overall_risk_score"] == risk["overall_risk_score"]

    asset_risks = client.get("/api/risk/assets").json()
    assert asset_risks and asset_risks[0]["factors"]
    path_risks = client.get("/api/risk/paths").json()
    assert path_risks and path_risks[0]["factors"]

    summary = {
        "health": health,
        "assets": len(assets),
        "relationships": len(rels),
        "vulnerabilities": len(vulns),
        "paths": paths["path_count"],
        "overall_risk": risk["overall_risk_score"],
        "overall_band": risk["overall_risk_band"],
        "scenario_c_sample": next(
            s
            for s in namesets
            if "Authentication Service" in s and "Cloud Application Server" in s
        ),
    }
    print(json.dumps(summary, indent=2))
    print("E2E_OK")


if __name__ == "__main__":
    main()
