"""Seed / reset the Smart Hospital synthetic dataset."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Allow running as `python -m seed.run_seed` from backend/
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from sqlalchemy import delete, func, select

from app.database import init_db
from app.database.session import SessionLocal
import json
from app.core.enums import AttackType
from app.models import (
    Asset,
    AssetRelationship,
    AssetService,
    AttackPathRecord,
    AttackScenario,
    PlatformUser,
    RiskAssessment,
    SimulationEvent,
    SimulationImpact,
    SimulationRun,
    Vulnerability,
)
from seed.smart_hospital_data import (
    A,
    ASSETS,
    EXPECTED_ASSET_COUNT,
    EXPECTED_RELATIONSHIP_COUNT,
    EXPECTED_VULNERABILITY_COUNT,
    PLATFORM_USERS,
    RELATIONSHIPS,
    VULNERABILITIES,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger("seed")


def clear_domain_data(db) -> None:
    """Remove seeded domain tables while preserving schema."""
    db.execute(delete(SimulationImpact))
    db.execute(delete(SimulationEvent))
    db.execute(delete(SimulationRun))
    db.execute(delete(AttackScenario))
    db.execute(delete(RiskAssessment))
    db.execute(delete(AttackPathRecord))
    db.execute(delete(Vulnerability))
    db.execute(delete(AssetRelationship))
    db.execute(delete(AssetService))
    db.execute(delete(Asset))
    db.execute(delete(PlatformUser))
    db.commit()


def seed_assets(db) -> int:
    for spec in ASSETS:
        asset = Asset(
            asset_id=spec.asset_id,
            asset_name=spec.asset_name,
            asset_type=spec.asset_type,
            layer=spec.layer,
            description=spec.description,
            ip_address=spec.ip_address,
            operating_system=spec.operating_system,
            criticality=spec.criticality,
            trust_level=spec.trust_level,
            status=spec.status,
        )
        for svc in spec.services:
            asset.services.append(
                AssetService(
                    service_name=svc.service_name,
                    protocol=svc.protocol,
                    port=svc.port,
                    description=svc.description,
                )
            )
        db.add(asset)
    db.commit()
    return db.scalar(select(func.count()).select_from(Asset)) or 0


def seed_relationships(db) -> int:
    for spec in RELATIONSHIPS:
        db.add(
            AssetRelationship(
                relationship_id=spec.relationship_id,
                source_asset_id=spec.source_asset_id,
                target_asset_id=spec.target_asset_id,
                relationship_type=spec.relationship_type,
                protocol=spec.protocol,
                port=spec.port,
                trust_level=spec.trust_level,
                description=spec.description,
            )
        )
    db.commit()
    return db.scalar(select(func.count()).select_from(AssetRelationship)) or 0


def seed_vulnerabilities(db) -> int:
    for spec in VULNERABILITIES:
        db.add(
            Vulnerability(
                vulnerability_id=spec.vulnerability_id,
                asset_id=spec.asset_id,
                identifier=spec.identifier,
                name=spec.name,
                description=spec.description,
                severity=spec.severity,
                cvss_score=spec.cvss_score,
                exploitability=spec.exploitability,
                status=spec.status,
                remediation=spec.remediation,
                is_synthetic=spec.is_synthetic,
            )
        )
    db.commit()
    return db.scalar(select(func.count()).select_from(Vulnerability)) or 0


def seed_users(db) -> int:
    for user in PLATFORM_USERS:
        db.add(PlatformUser(**user))
    db.commit()
    return db.scalar(select(func.count()).select_from(PlatformUser)) or 0


def seed_scenarios(db) -> int:
    scenarios = [
        AttackScenario(
            scenario_id="s1000000-0000-4000-8000-000000000001",
            scenario_code="SCEN-A",
            scenario_name="Scenario A — Medical IoT Device to Cloud App",
            description="Simulates attack propagation from bedside Patient Monitoring Device through IoT Gateway to Cloud Application Server.",
            source_asset_id=A["patient_monitor"],
            target_asset_id=A["cloud_app_server"],
            attack_type=AttackType.IOT_COMPROMISE,
            enabled=True,
            preferred_waypoints_json=json.dumps([A["patient_monitor"], A["iot_gateway"], A["cloud_app_server"]]),
            notes="Analytical propagation over synthetic HL7/MQTT/HTTPS connections.",
        ),
        AttackScenario(
            scenario_id="s1000000-0000-4000-8000-000000000002",
            scenario_code="SCEN-B",
            scenario_name="Scenario B — IoT Gateway to Patient Database",
            description="Simulates perimeter breach from IoT Gateway through Hospital Router, Firewall, Cloud Server, into Patient Database.",
            source_asset_id=A["iot_gateway"],
            target_asset_id=A["patient_db"],
            attack_type=AttackType.GATEWAY_PIVOT,
            enabled=True,
            preferred_waypoints_json=json.dumps([A["iot_gateway"], A["hospital_router"], A["hospital_firewall"], A["cloud_app_server"], A["patient_db"]]),
            notes="Demonstrates full multi-hop path traversal to sensitive clinical data.",
        ),
        AttackScenario(
            scenario_id="s1000000-0000-4000-8000-000000000003",
            scenario_code="SCEN-C",
            scenario_name="Scenario C — Doctor Portal User Account Compromise",
            description="Simulates identity-based breach starting from Doctor user asset through Doctor Portal, Auth Service, Cloud Server, to Patient Database.",
            source_asset_id=A["doctor"],
            target_asset_id=A["patient_db"],
            attack_type=AttackType.USER_COMPROMISE,
            enabled=True,
            preferred_waypoints_json=json.dumps([A["doctor"], A["doctor_portal"], A["auth_service"], A["cloud_app_server"], A["patient_db"]]),
            notes="Demonstrates credential access and authorization delegation path.",
        ),
        AttackScenario(
            scenario_id="s1000000-0000-4000-8000-000000000004",
            scenario_code="SCEN-D",
            scenario_name="Scenario D — Medical Sensor to Records DB (Blocked)",
            description="Demonstrates a blocked attack scenario where propagation from Medical Sensor is stopped by trust boundary conditions.",
            source_asset_id=A["medical_sensor"],
            target_asset_id=A["medical_records_db"],
            attack_type=AttackType.BLOCKED_DEMO,
            enabled=True,
            preferred_waypoints_json=json.dumps([A["medical_sensor"], A["iot_gateway"], A["hospital_router"], A["medical_records_db"]]),
            notes="Targeted scenario demonstrating defensive blocking rules.",
        ),
    ]
    for sc in scenarios:
        db.add(sc)
    db.commit()
    return db.scalar(select(func.count()).select_from(AttackScenario)) or 0


def run_seed(*, reset: bool = True) -> dict[str, int]:
    init_db()
    db = SessionLocal()
    try:
        if reset:
            logger.info("Clearing existing domain data...")
            clear_domain_data(db)

        assets = seed_assets(db)
        relationships = seed_relationships(db)
        vulnerabilities = seed_vulnerabilities(db)
        users = seed_users(db)
        scenarios = seed_scenarios(db)

        summary = {
            "assets": assets,
            "relationships": relationships,
            "vulnerabilities": vulnerabilities,
            "users": users,
            "scenarios": scenarios,
        }
        logger.info("Seed complete: %s", summary)

        assert assets == EXPECTED_ASSET_COUNT, f"assets={assets} expected={EXPECTED_ASSET_COUNT}"
        assert relationships == EXPECTED_RELATIONSHIP_COUNT
        assert vulnerabilities == EXPECTED_VULNERABILITY_COUNT
        assert scenarios >= 3
        return summary
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed SENTINEL-X Smart Hospital dataset")
    parser.add_argument(
        "--no-reset",
        action="store_true",
        help="Do not clear existing data before seeding (will fail on conflicts)",
    )
    args = parser.parse_args()
    run_seed(reset=not args.no_reset)


if __name__ == "__main__":
    main()
