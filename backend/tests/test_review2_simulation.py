"""Comprehensive backend tests for Review 2 Attack Simulation Engine, Scenarios, and APIs."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.enums import SimulationResult
from app.database import get_db
from app.main import app
from app.simulation import SecurityMappingService, SimulationEngine
from seed.run_seed import run_seed
from seed.smart_hospital_data import A

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_seed():
    """Ensure clean Smart Hospital seed before each test."""
    run_seed(reset=True)


def test_list_scenarios():
    response = client.get("/api/scenarios")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 4
    codes = [s["scenario_code"] for s in data]
    assert "SCEN-A" in codes
    assert "SCEN-B" in codes
    assert "SCEN-C" in codes
    assert "SCEN-D" in codes


def test_get_scenario():
    scenarios = client.get("/api/scenarios").json()
    sc_id = scenarios[0]["scenario_id"]
    res = client.get(f"/api/scenarios/{sc_id}")
    assert res.status_code == 200
    assert res.json()["scenario_id"] == sc_id


def test_run_successful_simulation():
    # Run Scenario B: IoT Gateway -> Patient Database
    scenarios = client.get("/api/scenarios").json()
    scen_b = next(s for s in scenarios if s["scenario_code"] == "SCEN-B")

    response = client.post("/api/simulations", json={"scenario_id": scen_b["scenario_id"]})
    assert response.status_code == 201
    sim = response.json()

    assert sim["result"] == "SUCCESS"
    assert sim["target_reached"] is True
    assert len(sim["path_asset_ids"]) >= 4
    assert len(sim["compromised_asset_ids"]) >= 4
    assert A["patient_db"] in sim["compromised_asset_ids"]
    assert len(sim["events"]) >= 4

    # Check impact metrics
    impact = sim["impact"]
    assert impact is not None
    assert impact["target_reached"] is True
    assert impact["compromised_count"] >= 4
    assert impact["impact_score"] > 0

    # Check risk comparison
    comp = sim["risk_comparison"]
    assert comp is not None
    assert comp["baseline_risk"] > 0
    assert comp["simulation_risk"] > 0


def test_run_blocked_simulation():
    # Run Scenario D: Medical Sensor -> Records DB
    scenarios = client.get("/api/scenarios").json()
    scen_d = next(s for s in scenarios if s["scenario_code"] == "SCEN-D")

    response = client.post("/api/simulations", json={"scenario_id": scen_d["scenario_id"]})
    assert response.status_code == 201
    sim = response.json()

    assert sim["result"] == "BLOCKED"
    assert sim["target_reached"] is False
    assert sim["block_reason"] is not None
    assert "BLOCKED" in sim["block_reason"] or "blocked" in sim["block_reason"].lower()


def test_simulation_history_and_detail_endpoints():
    scenarios = client.get("/api/scenarios").json()
    scen_a = next(s for s in scenarios if s["scenario_code"] == "SCEN-A")

    # Trigger a run
    run_res = client.post("/api/simulations", json={"scenario_id": scen_a["scenario_id"]})
    sim_id = run_res.json()["simulation_id"]

    # History
    history = client.get("/api/simulations").json()
    assert len(history) >= 1
    assert history[0]["simulation_id"] == sim_id

    # Get run details
    detail = client.get(f"/api/simulations/{sim_id}").json()
    assert detail["simulation_id"] == sim_id

    # Get events
    events = client.get(f"/api/simulations/{sim_id}/events").json()
    assert len(events) >= 1

    # Get impact
    impact = client.get(f"/api/simulations/{sim_id}/impact").json()
    assert impact["simulation_id"] == sim_id

    # Get risk comparison via simulations endpoint & risk endpoint
    comp1 = client.get(f"/api/simulations/{sim_id}/risk-comparison").json()
    comp2 = client.get(f"/api/risk/comparison?simulation_id={sim_id}").json()
    assert comp1["simulation_id"] == sim_id
    assert comp2["simulation_id"] == sim_id


def test_ad_hoc_simulation():
    # Run without scenario ID, specifying source and target directly
    payload = {
        "source_asset_id": A["patient_monitor"],
        "target_asset_id": A["cloud_app_server"],
    }
    response = client.post("/api/simulations", json=payload)
    assert response.status_code == 201
    sim = response.json()
    assert sim["result"] in ["SUCCESS", "BLOCKED"]


def test_blast_radius_and_security_profile():
    # Test SecurityMappingService directly
    db = next(get_db())
    try:
        service = SecurityMappingService(db)
        radius = service.blast_radius(A["iot_gateway"])
        assert radius.origin_asset_id == A["iot_gateway"]
        assert radius.reachable_asset_count >= 2
        assert radius.impact_score > 0

        profile = service.profile(A["iot_gateway"])
        assert profile.asset_id == A["iot_gateway"]
        assert profile.relationship_count >= 2
    finally:
        db.close()
