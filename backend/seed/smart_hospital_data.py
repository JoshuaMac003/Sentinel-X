"""Deterministic Smart Hospital synthetic seed data for SENTINEL-X Review 1.

All data is fictional. No real patient information. No invented CVE IDs.
Vulnerability identifiers use the SYN-* prefix.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from app.core.enums import (
    AssetLayer,
    AssetStatus,
    AssetType,
    Criticality,
    Exploitability,
    PlatformRole,
    RelationshipType,
    Severity,
    TrustLevel,
    VulnerabilityStatus,
)


# ---------------------------------------------------------------------------
# Stable IDs — keep seed deterministic across resets
# ---------------------------------------------------------------------------

A = {
    "patient_monitor": "a1000000-0000-4000-8000-000000000001",
    "ecg_monitor": "a1000000-0000-4000-8000-000000000002",
    "smart_bed": "a1000000-0000-4000-8000-000000000003",
    "medical_sensor": "a1000000-0000-4000-8000-000000000004",
    "iot_gateway": "a1000000-0000-4000-8000-000000000010",
    "hospital_router": "a1000000-0000-4000-8000-000000000020",
    "hospital_firewall": "a1000000-0000-4000-8000-000000000021",
    "cloud_app_server": "a1000000-0000-4000-8000-000000000030",
    "hospital_web_app": "a1000000-0000-4000-8000-000000000031",
    "doctor_portal": "a1000000-0000-4000-8000-000000000032",
    "auth_service": "a1000000-0000-4000-8000-000000000033",
    "patient_db": "a1000000-0000-4000-8000-000000000040",
    "medical_records_db": "a1000000-0000-4000-8000-000000000041",
    "doctor": "a1000000-0000-4000-8000-000000000050",
    "nurse": "a1000000-0000-4000-8000-000000000051",
    "admin": "a1000000-0000-4000-8000-000000000052",
}


@dataclass
class ServiceSpec:
    service_name: str
    protocol: Optional[str] = None
    port: Optional[int] = None
    description: Optional[str] = None


@dataclass
class AssetSpec:
    asset_id: str
    asset_name: str
    asset_type: AssetType
    layer: AssetLayer
    criticality: Criticality
    description: str
    ip_address: Optional[str] = None
    operating_system: Optional[str] = None
    trust_level: TrustLevel = TrustLevel.MEDIUM
    status: AssetStatus = AssetStatus.ACTIVE
    services: list[ServiceSpec] = field(default_factory=list)


@dataclass
class RelationshipSpec:
    relationship_id: str
    source_asset_id: str
    target_asset_id: str
    relationship_type: RelationshipType
    protocol: Optional[str] = None
    port: Optional[int] = None
    trust_level: TrustLevel = TrustLevel.MEDIUM
    description: Optional[str] = None


@dataclass
class VulnerabilitySpec:
    vulnerability_id: str
    asset_id: str
    identifier: str
    name: str
    description: str
    severity: Severity
    cvss_score: float
    exploitability: Exploitability
    remediation: str
    status: VulnerabilityStatus = VulnerabilityStatus.OPEN
    is_synthetic: bool = True


ASSETS: list[AssetSpec] = [
    AssetSpec(
        A["patient_monitor"],
        "Patient Monitoring Device",
        AssetType.IOT_DEVICE,
        AssetLayer.IOT,
        Criticality.HIGH,
        "Synthetic bedside vital-signs monitor (demo).",
        "10.10.1.11",
        "Embedded RTOS",
        TrustLevel.LOW,
        services=[ServiceSpec("mqtt-telemetry", "MQTT", 1883), ServiceSpec("http-mgmt", "HTTP", 8080)],
    ),
    AssetSpec(
        A["ecg_monitor"],
        "ECG Monitor",
        AssetType.IOT_DEVICE,
        AssetLayer.IOT,
        Criticality.HIGH,
        "Synthetic ECG acquisition device (demo).",
        "10.10.1.12",
        "Embedded Linux",
        TrustLevel.LOW,
        services=[ServiceSpec("hl7-stream", "TCP", 2575)],
    ),
    AssetSpec(
        A["smart_bed"],
        "Smart Bed",
        AssetType.IOT_DEVICE,
        AssetLayer.IOT,
        Criticality.MEDIUM,
        "Synthetic smart bed controller (demo).",
        "10.10.1.13",
        "Firmware v2",
        TrustLevel.LOW,
        services=[ServiceSpec("coap", "UDP", 5683)],
    ),
    AssetSpec(
        A["medical_sensor"],
        "Medical Sensor",
        AssetType.IOT_DEVICE,
        AssetLayer.IOT,
        Criticality.MEDIUM,
        "Synthetic wearable/medical sensor node (demo).",
        "10.10.1.14",
        "TinyOS",
        TrustLevel.UNTRUSTED,
        services=[ServiceSpec("ble-bridge", "BLE", None)],
    ),
    AssetSpec(
        A["iot_gateway"],
        "IoT Gateway",
        AssetType.GATEWAY,
        AssetLayer.EDGE,
        Criticality.HIGH,
        "Aggregates IoT telemetry and bridges to hospital network (demo).",
        "10.10.2.1",
        "Linux",
        TrustLevel.MEDIUM,
        services=[
            ServiceSpec("mqtt-broker", "MQTT", 1883),
            ServiceSpec("https-uplink", "HTTPS", 443),
        ],
    ),
    AssetSpec(
        A["hospital_router"],
        "Hospital Router",
        AssetType.ROUTER,
        AssetLayer.NETWORK,
        Criticality.HIGH,
        "Core routing for hospital LAN segments (demo).",
        "10.10.0.1",
        "Cisco IOS (synthetic)",
        TrustLevel.HIGH,
        services=[ServiceSpec("ssh", "TCP", 22)],
    ),
    AssetSpec(
        A["hospital_firewall"],
        "Hospital Firewall",
        AssetType.FIREWALL,
        AssetLayer.NETWORK,
        Criticality.CRITICAL,
        "Perimeter filtering between hospital LAN and cloud edge (demo).",
        "10.10.0.2",
        "pfSense (synthetic)",
        TrustLevel.HIGH,
        services=[ServiceSpec("https-admin", "HTTPS", 8443)],
    ),
    AssetSpec(
        A["cloud_app_server"],
        "Cloud Application Server",
        AssetType.SERVER,
        AssetLayer.CLOUD,
        Criticality.CRITICAL,
        "Hosts clinical application workloads in cloud VPC (demo).",
        "10.20.0.10",
        "Ubuntu Server 22.04",
        TrustLevel.HIGH,
        services=[ServiceSpec("https", "HTTPS", 443), ServiceSpec("ssh", "TCP", 22)],
    ),
    AssetSpec(
        A["hospital_web_app"],
        "Hospital Web Application",
        AssetType.APPLICATION,
        AssetLayer.APPLICATION,
        Criticality.HIGH,
        "Public-facing hospital informational/clinical web app (demo).",
        None,
        "Node.js",
        TrustLevel.MEDIUM,
        services=[ServiceSpec("https", "HTTPS", 443)],
    ),
    AssetSpec(
        A["doctor_portal"],
        "Doctor Portal",
        AssetType.APPLICATION,
        AssetLayer.APPLICATION,
        Criticality.HIGH,
        "Clinician portal for chart review (demo).",
        None,
        "React SPA + API",
        TrustLevel.MEDIUM,
        services=[ServiceSpec("https", "HTTPS", 443)],
    ),
    AssetSpec(
        A["auth_service"],
        "Authentication Service",
        AssetType.CLOUD_SERVICE,
        AssetLayer.CLOUD,
        Criticality.CRITICAL,
        "Identity provider for hospital applications (demo).",
        "10.20.0.20",
        "Keycloak (synthetic)",
        TrustLevel.HIGH,
        services=[ServiceSpec("oidc", "HTTPS", 8443)],
    ),
    AssetSpec(
        A["patient_db"],
        "Patient Database",
        AssetType.DATABASE,
        AssetLayer.DATA,
        Criticality.CRITICAL,
        "Synthetic patient demographics store — no real PHI.",
        "10.20.1.10",
        "PostgreSQL",
        TrustLevel.HIGH,
        services=[ServiceSpec("postgres", "TCP", 5432)],
    ),
    AssetSpec(
        A["medical_records_db"],
        "Medical Records Database",
        AssetType.DATABASE,
        AssetLayer.DATA,
        Criticality.CRITICAL,
        "Synthetic EHR/records store — fictional records only.",
        "10.20.1.11",
        "PostgreSQL",
        TrustLevel.HIGH,
        services=[ServiceSpec("postgres", "TCP", 5432)],
    ),
    AssetSpec(
        A["doctor"],
        "Doctor",
        AssetType.USER,
        AssetLayer.USER,
        Criticality.MEDIUM,
        "Synthetic clinician identity for access-path analysis (demo).",
        None,
        None,
        TrustLevel.MEDIUM,
    ),
    AssetSpec(
        A["nurse"],
        "Nurse",
        AssetType.USER,
        AssetLayer.USER,
        Criticality.MEDIUM,
        "Synthetic nursing identity for access-path analysis (demo).",
        None,
        None,
        TrustLevel.MEDIUM,
    ),
    AssetSpec(
        A["admin"],
        "Hospital Administrator",
        AssetType.USER,
        AssetLayer.USER,
        Criticality.HIGH,
        "Synthetic hospital IT/admin identity (demo).",
        None,
        None,
        TrustLevel.HIGH,
    ),
]


RELATIONSHIPS: list[RelationshipSpec] = [
    # IoT → Gateway
    RelationshipSpec("r1000000-0000-4000-8000-000000000001", A["patient_monitor"], A["iot_gateway"], RelationshipType.COMMUNICATES_WITH, "MQTT", 1883, TrustLevel.LOW, "Telemetry uplink"),
    RelationshipSpec("r1000000-0000-4000-8000-000000000002", A["ecg_monitor"], A["iot_gateway"], RelationshipType.COMMUNICATES_WITH, "TCP", 2575, TrustLevel.LOW, "ECG stream"),
    RelationshipSpec("r1000000-0000-4000-8000-000000000003", A["smart_bed"], A["iot_gateway"], RelationshipType.COMMUNICATES_WITH, "UDP", 5683, TrustLevel.LOW, "Bed status"),
    RelationshipSpec("r1000000-0000-4000-8000-000000000004", A["medical_sensor"], A["iot_gateway"], RelationshipType.COMMUNICATES_WITH, "MQTT", 1883, TrustLevel.UNTRUSTED, "Sensor readings"),
    # Gateway → Network → Cloud
    RelationshipSpec("r1000000-0000-4000-8000-000000000010", A["iot_gateway"], A["hospital_router"], RelationshipType.CONNECTS_TO, "IP", None, TrustLevel.MEDIUM, "LAN uplink"),
    RelationshipSpec("r1000000-0000-4000-8000-000000000011", A["hospital_router"], A["hospital_firewall"], RelationshipType.CONNECTS_TO, "IP", None, TrustLevel.HIGH, "Perimeter path"),
    RelationshipSpec("r1000000-0000-4000-8000-000000000012", A["hospital_firewall"], A["cloud_app_server"], RelationshipType.CONNECTS_TO, "HTTPS", 443, TrustLevel.MEDIUM, "Allowed cloud egress"),
    # Applications hosted / auth
    RelationshipSpec("r1000000-0000-4000-8000-000000000020", A["cloud_app_server"], A["hospital_web_app"], RelationshipType.HOSTS, "HTTPS", 443, TrustLevel.HIGH, "Hosts web app"),
    RelationshipSpec("r1000000-0000-4000-8000-000000000021", A["cloud_app_server"], A["doctor_portal"], RelationshipType.HOSTS, "HTTPS", 443, TrustLevel.HIGH, "Hosts doctor portal"),
    RelationshipSpec("r1000000-0000-4000-8000-000000000022", A["cloud_app_server"], A["auth_service"], RelationshipType.DEPENDS_ON, "HTTPS", 8443, TrustLevel.HIGH, "Auth dependency"),
    RelationshipSpec("r1000000-0000-4000-8000-000000000023", A["hospital_web_app"], A["auth_service"], RelationshipType.AUTHENTICATES_TO, "OIDC", 8443, TrustLevel.HIGH, "Web SSO"),
    RelationshipSpec("r1000000-0000-4000-8000-000000000024", A["doctor_portal"], A["auth_service"], RelationshipType.AUTHENTICATES_TO, "OIDC", 8443, TrustLevel.HIGH, "Portal SSO"),
    # Auth issues tokens / grants access into cloud application tier (analytical trust edge).
    RelationshipSpec("r1000000-0000-4000-8000-000000000025", A["auth_service"], A["cloud_app_server"], RelationshipType.CONNECTS_TO, "HTTPS", 443, TrustLevel.HIGH, "IdP authorizes access to cloud apps"),
    # Data access
    RelationshipSpec("r1000000-0000-4000-8000-000000000030", A["cloud_app_server"], A["patient_db"], RelationshipType.ACCESSES, "TCP", 5432, TrustLevel.HIGH, "App → patient DB"),
    RelationshipSpec("r1000000-0000-4000-8000-000000000031", A["cloud_app_server"], A["medical_records_db"], RelationshipType.ACCESSES, "TCP", 5432, TrustLevel.HIGH, "App → records DB"),
    RelationshipSpec("r1000000-0000-4000-8000-000000000032", A["doctor_portal"], A["patient_db"], RelationshipType.ACCESSES, "HTTPS", 443, TrustLevel.MEDIUM, "Portal queries patient data"),
    RelationshipSpec("r1000000-0000-4000-8000-000000000033", A["doctor_portal"], A["medical_records_db"], RelationshipType.ACCESSES, "HTTPS", 443, TrustLevel.MEDIUM, "Portal queries records"),
    RelationshipSpec("r1000000-0000-4000-8000-000000000034", A["hospital_web_app"], A["patient_db"], RelationshipType.ACCESSES, "HTTPS", 443, TrustLevel.LOW, "Limited patient lookups"),
    # Users
    RelationshipSpec("r1000000-0000-4000-8000-000000000040", A["doctor"], A["doctor_portal"], RelationshipType.ACCESSES, "HTTPS", 443, TrustLevel.MEDIUM, "Clinician login"),
    RelationshipSpec("r1000000-0000-4000-8000-000000000041", A["nurse"], A["hospital_web_app"], RelationshipType.ACCESSES, "HTTPS", 443, TrustLevel.MEDIUM, "Nurse workstation access"),
    RelationshipSpec("r1000000-0000-4000-8000-000000000042", A["admin"], A["hospital_firewall"], RelationshipType.MANAGES, "HTTPS", 8443, TrustLevel.HIGH, "Admin manages firewall"),
    RelationshipSpec("r1000000-0000-4000-8000-000000000043", A["admin"], A["cloud_app_server"], RelationshipType.MANAGES, "SSH", 22, TrustLevel.HIGH, "Admin manages cloud server"),
    RelationshipSpec("r1000000-0000-4000-8000-000000000044", A["admin"], A["auth_service"], RelationshipType.MANAGES, "HTTPS", 8443, TrustLevel.HIGH, "Admin manages IdP"),
]


VULNERABILITIES: list[VulnerabilitySpec] = [
    VulnerabilitySpec("v1000000-0000-4000-8000-000000000001", A["patient_monitor"], "SYN-AUTH-001", "Weak Authentication", "Default or weak device credentials on management interface (synthetic).", Severity.HIGH, 7.5, Exploitability.HIGH, "Enforce unique credentials and disable default accounts."),
    VulnerabilitySpec("v1000000-0000-4000-8000-000000000002", A["patient_monitor"], "SYN-FW-001", "Outdated Firmware", "Device firmware missing recent security patches (synthetic).", Severity.MEDIUM, 5.8, Exploitability.MEDIUM, "Apply vendor firmware updates in maintenance window."),
    VulnerabilitySpec("v1000000-0000-4000-8000-000000000003", A["ecg_monitor"], "SYN-CRYPTO-001", "Unencrypted Telemetry", "Clinical telemetry transmitted without TLS (synthetic).", Severity.HIGH, 7.1, Exploitability.MEDIUM, "Enable TLS for HL7/MQTT streams."),
    VulnerabilitySpec("v1000000-0000-4000-8000-000000000004", A["smart_bed"], "SYN-CFG-001", "Insecure Configuration", "Debug services left enabled on device (synthetic).", Severity.MEDIUM, 5.3, Exploitability.HIGH, "Disable debug ports and harden configuration."),
    VulnerabilitySpec("v1000000-0000-4000-8000-000000000005", A["medical_sensor"], "SYN-BLE-001", "Weak Pairing", "Predictable BLE pairing material (synthetic).", Severity.MEDIUM, 6.0, Exploitability.HIGH, "Require authenticated pairing and rotate keys."),
    VulnerabilitySpec("v1000000-0000-4000-8000-000000000006", A["iot_gateway"], "SYN-AUTH-002", "Exposed Management API", "Gateway admin API reachable without MFA (synthetic).", Severity.HIGH, 8.1, Exploitability.HIGH, "Require MFA and restrict management to jump hosts."),
    VulnerabilitySpec("v1000000-0000-4000-8000-000000000007", A["iot_gateway"], "SYN-INJ-001", "Command Injection Risk", "Unvalidated input in diagnostic endpoint (synthetic).", Severity.CRITICAL, 9.0, Exploitability.MEDIUM, "Sanitize inputs; remove diagnostic shell."),
    VulnerabilitySpec("v1000000-0000-4000-8000-000000000008", A["hospital_router"], "SYN-ACL-001", "Permissive ACL", "Overly broad routing ACL between IoT and clinical VLANs (synthetic).", Severity.MEDIUM, 5.5, Exploitability.MEDIUM, "Segment VLANs and tighten ACL rules."),
    VulnerabilitySpec("v1000000-0000-4000-8000-000000000009", A["hospital_firewall"], "SYN-RULE-001", "Misconfigured Firewall Rule", "Broad allow rule for cloud egress (synthetic).", Severity.HIGH, 7.2, Exploitability.MEDIUM, "Restrict destinations and enforce TLS inspection policy."),
    VulnerabilitySpec("v1000000-0000-4000-8000-000000000010", A["cloud_app_server"], "SYN-PATCH-001", "Missing Security Patches", "OS packages behind recommended baseline (synthetic).", Severity.HIGH, 7.8, Exploitability.MEDIUM, "Enable automated patching and vulnerability scanning."),
    VulnerabilitySpec("v1000000-0000-4000-8000-000000000011", A["hospital_web_app"], "SYN-XSS-001", "Reflected XSS", "Input reflected without encoding on search page (synthetic).", Severity.MEDIUM, 6.1, Exploitability.HIGH, "Encode outputs and deploy CSP."),
    VulnerabilitySpec("v1000000-0000-4000-8000-000000000012", A["doctor_portal"], "SYN-SESS-001", "Session Fixation", "Session tokens not rotated after login (synthetic).", Severity.HIGH, 7.4, Exploitability.MEDIUM, "Rotate session IDs post-authentication."),
    VulnerabilitySpec("v1000000-0000-4000-8000-000000000013", A["auth_service"], "SYN-MFA-001", "MFA Not Enforced", "Privileged accounts can authenticate without MFA (synthetic).", Severity.CRITICAL, 8.8, Exploitability.HIGH, "Enforce MFA for all privileged roles."),
    VulnerabilitySpec("v1000000-0000-4000-8000-000000000014", A["patient_db"], "SYN-DB-001", "Excessive Privileges", "Application DB role has unnecessary DDL rights (synthetic).", Severity.HIGH, 7.0, Exploitability.LOW, "Apply least-privilege DB roles."),
    VulnerabilitySpec("v1000000-0000-4000-8000-000000000015", A["medical_records_db"], "SYN-ENC-001", "Encryption at Rest Disabled", "Disk encryption not enabled for demo volume (synthetic).", Severity.MEDIUM, 5.9, Exploitability.LOW, "Enable volume encryption and key rotation.", status=VulnerabilityStatus.CLOSED),
    VulnerabilitySpec("v1000000-0000-4000-8000-000000000016", A["doctor"], "SYN-PHISH-001", "Phishing Susceptibility", "User account modeled with weak phishing resistance (synthetic analytical attribute).", Severity.MEDIUM, 4.5, Exploitability.HIGH, "Security awareness training and phishing-resistant MFA."),
]


PLATFORM_USERS = [
    {
        "user_id": "u1000000-0000-4000-8000-000000000001",
        "username": "analyst",
        "display_name": "Security Analyst (Demo)",
        "role": PlatformRole.ANALYST,
        "email": "analyst@sentinel-x.demo",
    },
    {
        "user_id": "u1000000-0000-4000-8000-000000000002",
        "username": "admin",
        "display_name": "Platform Admin (Demo)",
        "role": PlatformRole.ADMIN,
        "email": "admin@sentinel-x.demo",
    },
]

# Expected counts for verification
EXPECTED_ASSET_COUNT = len(ASSETS)
EXPECTED_RELATIONSHIP_COUNT = len(RELATIONSHIPS)
EXPECTED_VULNERABILITY_COUNT = len(VULNERABILITIES)
