"""Integration tests for seed, digital twin, attack graph, and risk."""

from fastapi.testclient import TestClient

from seed.smart_hospital_data import (
    EXPECTED_ASSET_COUNT,
    EXPECTED_RELATIONSHIP_COUNT,
    EXPECTED_VULNERABILITY_COUNT,
    A,
)
from seed.run_seed import run_seed


def _seeded_client(client: TestClient) -> None:
    run_seed(reset=True)


def test_seed_and_inventory(client: TestClient):
    _seeded_client(client)
    assets = client.get("/api/assets").json()
    relationships = client.get("/api/relationships").json()
    vulns = client.get("/api/vulnerabilities").json()
    assert len(assets) == EXPECTED_ASSET_COUNT
    assert len(relationships) == EXPECTED_RELATIONSHIP_COUNT
    assert len(vulns) == EXPECTED_VULNERABILITY_COUNT
    assert all(v["identifier"].startswith("SYN-") for v in vulns)
    assert all(v["is_synthetic"] is True for v in vulns)


def test_digital_twin_matches_database(client: TestClient):
    _seeded_client(client)
    twin = client.get("/api/digital-twin").json()
    assert twin["asset_count"] == EXPECTED_ASSET_COUNT
    assert twin["relationship_count"] == EXPECTED_RELATIONSHIP_COUNT
    assert twin["vulnerability_count"] == EXPECTED_VULNERABILITY_COUNT
    assert len(twin["assets"]) == EXPECTED_ASSET_COUNT
    assert len(twin["relationships"]) == EXPECTED_RELATIONSHIP_COUNT
    assert twin["topology"]["nodes"]
    assert twin["topology"]["edges"]
    assert twin["topology"]["layers"]

    # Twin updates when DB changes
    asset_id = twin["assets"][0]["asset_id"]
    client.put(f"/api/assets/{asset_id}", json={"status": "MAINTENANCE"})
    twin2 = client.get("/api/digital-twin").json()
    updated = next(a for a in twin2["assets"] if a["asset_id"] == asset_id)
    assert updated["status"] == "MAINTENANCE"


def test_attack_graph_and_scenario_paths(client: TestClient):
    _seeded_client(client)
    graph = client.get("/api/attack-graph").json()
    assert graph["node_count"] == EXPECTED_ASSET_COUNT
    assert graph["edge_count"] == EXPECTED_RELATIONSHIP_COUNT
    assert graph["nodes"]
    assert graph["edges"]

    paths = client.get("/api/attack-paths").json()
    assert paths["path_count"] > 0
    labels = {p.get("scenario_label") for p in paths["paths"]}
    assert any(label and "Scenario A" in label for label in labels)
    assert any(label and "Scenario B" in label for label in labels)
    assert any(label and "Scenario C" in label for label in labels)

    # Explicit path discovery is dynamic (not a hard-coded string list)
    explicit = client.get(
        "/api/attack-paths",
        params={
            "source_asset_id": A["patient_monitor"],
            "target_asset_id": A["cloud_app_server"],
        },
    ).json()
    assert explicit["path_count"] >= 1
    for path in explicit["paths"]:
        assert path["asset_ids"][0] == A["patient_monitor"]
        assert path["asset_ids"][-1] == A["cloud_app_server"]
        assert "IoT Gateway" in " ".join(h["asset_name"] for h in path["hops"])


def test_baseline_risk_explainable(client: TestClient):
    _seeded_client(client)
    overview = client.get("/api/risk/overview").json()
    assert 0 <= overview["overall_risk_score"] <= 100
    assert overview["model_version"] == "baseline-v1"
    assert overview["assessed_assets"] == EXPECTED_ASSET_COUNT
    assert overview["factors_summary"]
    assert "not ML" in overview["explanation"] or "not ML" in " ".join(overview["notes"]).lower() or "rule-based" in overview["explanation"]

    assets = client.get("/api/risk/assets").json()
    assert len(assets) == EXPECTED_ASSET_COUNT
    assert assets[0]["factors"]
    assert assets[0]["explanation"]

    paths = client.get("/api/risk/paths").json()
    assert len(paths) >= 1
    assert paths[0]["factors"]
    assert 0 <= paths[0]["risk_score"] <= 100


def test_admin_seed_endpoint(client: TestClient):
    response = client.post("/api/admin/seed")
    assert response.status_code == 200
    body = response.json()
    assert body["assets"] == EXPECTED_ASSET_COUNT
    assert body["relationships"] == EXPECTED_RELATIONSHIP_COUNT
    assert body["vulnerabilities"] == EXPECTED_VULNERABILITY_COUNT
