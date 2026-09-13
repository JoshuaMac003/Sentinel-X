from fastapi.testclient import TestClient


def test_health(client: TestClient):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["app"] == "SENTINEL-X"
    assert body["database"] == "sqlite"


def test_asset_crud_relationship_and_vulnerability(client: TestClient):
    create_payload = {
        "asset_name": "Test IoT Gateway",
        "asset_type": "GATEWAY",
        "layer": "EDGE",
        "description": "Phase 1 test asset",
        "ip_address": "10.0.0.1",
        "operating_system": "Linux",
        "criticality": 4,
        "trust_level": "MEDIUM",
        "status": "ACTIVE",
        "services": [
            {
                "service_name": "mqtt",
                "protocol": "TCP",
                "port": 1883,
            }
        ],
    }
    created = client.post("/api/assets", json=create_payload)
    assert created.status_code == 201, created.text
    asset = created.json()
    asset_id = asset["asset_id"]
    assert asset["asset_name"] == "Test IoT Gateway"
    assert len(asset["services"]) == 1

    listed = client.get("/api/assets")
    assert listed.status_code == 200
    assert any(a["asset_id"] == asset_id for a in listed.json())

    fetched = client.get(f"/api/assets/{asset_id}")
    assert fetched.status_code == 200
    assert fetched.json()["criticality"] == 4

    target = client.post(
        "/api/assets",
        json={
            "asset_name": "Test Cloud Server",
            "asset_type": "SERVER",
            "layer": "CLOUD",
            "criticality": 5,
        },
    )
    assert target.status_code == 201, target.text
    target_id = target.json()["asset_id"]

    rel = client.post(
        "/api/relationships",
        json={
            "source_asset_id": asset_id,
            "target_asset_id": target_id,
            "relationship_type": "CONNECTS_TO",
            "protocol": "TLS",
            "port": 443,
            "trust_level": "MEDIUM",
        },
    )
    assert rel.status_code == 201, rel.text

    relationships = client.get("/api/relationships")
    assert relationships.status_code == 200
    assert len(relationships.json()) == 1

    vuln = client.post(
        "/api/vulnerabilities",
        json={
            "asset_id": asset_id,
            "identifier": "SYN-AUTH-001",
            "name": "Weak Authentication",
            "description": "Synthetic demonstration vulnerability",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "exploitability": "HIGH",
            "status": "OPEN",
            "remediation": "Enforce MFA and rotate credentials",
            "is_synthetic": True,
        },
    )
    assert vuln.status_code == 201, vuln.text

    vulns = client.get("/api/vulnerabilities")
    assert vulns.status_code == 200
    assert len(vulns.json()) == 1

    bad = client.post(
        "/api/vulnerabilities",
        json={
            "asset_id": asset_id,
            "identifier": "CVE-2024-99999",
            "name": "Invented",
            "severity": "HIGH",
            "cvss_score": 7.0,
            "exploitability": "HIGH",
            "is_synthetic": True,
        },
    )
    assert bad.status_code == 400

    twin = client.get("/api/digital-twin")
    assert twin.status_code == 200
    # Empty DB twin is still a valid dynamic snapshot
    assert "asset_count" in twin.json()

    graph = client.get("/api/attack-graph")
    assert graph.status_code == 200
    assert "nodes" in graph.json()

    risk = client.get("/api/risk/overview")
    assert risk.status_code == 200
    assert "overall_risk_score" in risk.json()

    updated = client.put(
        f"/api/assets/{asset_id}",
        json={"status": "MAINTENANCE", "description": "Updated in Phase 1 test"},
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "MAINTENANCE"

    deleted = client.delete(f"/api/assets/{asset_id}")
    assert deleted.status_code == 200

    missing = client.get(f"/api/assets/{asset_id}")
    assert missing.status_code == 404
