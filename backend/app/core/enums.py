"""Domain enumerations — avoid scattered hard-coded strings."""

from enum import Enum, IntEnum


class AssetType(str, Enum):
    IOT_DEVICE = "IOT_DEVICE"
    GATEWAY = "GATEWAY"
    ROUTER = "ROUTER"
    FIREWALL = "FIREWALL"
    SERVER = "SERVER"
    APPLICATION = "APPLICATION"
    DATABASE = "DATABASE"
    USER = "USER"
    CLOUD_SERVICE = "CLOUD_SERVICE"


class AssetLayer(str, Enum):
    IOT = "IOT"
    EDGE = "EDGE"
    NETWORK = "NETWORK"
    CLOUD = "CLOUD"
    APPLICATION = "APPLICATION"
    DATA = "DATA"
    USER = "USER"


class AssetStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    MAINTENANCE = "MAINTENANCE"
    COMPROMISED = "COMPROMISED"
    UNKNOWN = "UNKNOWN"


class Criticality(IntEnum):
    VERY_LOW = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class RelationshipType(str, Enum):
    COMMUNICATES_WITH = "COMMUNICATES_WITH"
    CONNECTS_TO = "CONNECTS_TO"
    ACCESSES = "ACCESSES"
    AUTHENTICATES_TO = "AUTHENTICATES_TO"
    DEPENDS_ON = "DEPENDS_ON"
    MANAGES = "MANAGES"
    HOSTS = "HOSTS"


class TrustLevel(str, Enum):
    UNTRUSTED = "UNTRUSTED"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    FULL = "FULL"


class Severity(str, Enum):
    VERY_LOW = "VERY_LOW"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Exploitability(str, Enum):
    VERY_LOW = "VERY_LOW"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VulnerabilityStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    MITIGATED = "MITIGATED"
    ACCEPTED = "ACCEPTED"
    CLOSED = "CLOSED"


class RiskBand(str, Enum):
    VERY_LOW = "VERY_LOW"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackStage(str, Enum):
    INITIAL_ACCESS = "INITIAL_ACCESS"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DATA_ACCESS = "DATA_ACCESS"
    IMPACT = "IMPACT"


class PlatformRole(str, Enum):
    VIEWER = "VIEWER"
    ANALYST = "ANALYST"
    ADMIN = "ADMIN"


class SimulationState(str, Enum):
    """Isolated simulation overlay — does not permanently alter baseline assets."""

    NORMAL = "NORMAL"
    COMPROMISED = "COMPROMISED"
    ISOLATED = "ISOLATED"
    RECOVERED = "RECOVERED"


class SimulationResult(str, Enum):
    SUCCESS = "SUCCESS"
    BLOCKED = "BLOCKED"
    NO_PATH = "NO_PATH"
    FAILED = "FAILED"


class AttackType(str, Enum):
    IOT_COMPROMISE = "IOT_COMPROMISE"
    GATEWAY_PIVOT = "GATEWAY_PIVOT"
    USER_COMPROMISE = "USER_COMPROMISE"
    BLOCKED_DEMO = "BLOCKED_DEMO"
    AD_HOC = "AD_HOC"


class SimulationAction(str, Enum):
    VALIDATE = "VALIDATE"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    PROPAGATE = "PROPAGATE"
    BLOCK = "BLOCK"
    TARGET_REACHED = "TARGET_REACHED"


# Numeric mappings for explainable baseline risk (0–1 scale inputs).
SEVERITY_SCORE: dict[Severity, float] = {
    Severity.VERY_LOW: 0.1,
    Severity.LOW: 0.3,
    Severity.MEDIUM: 0.5,
    Severity.HIGH: 0.75,
    Severity.CRITICAL: 1.0,
}

EXPLOITABILITY_SCORE: dict[Exploitability, float] = {
    Exploitability.VERY_LOW: 0.1,
    Exploitability.LOW: 0.3,
    Exploitability.MEDIUM: 0.5,
    Exploitability.HIGH: 0.75,
    Exploitability.CRITICAL: 1.0,
}

CRITICALITY_SCORE: dict[Criticality, float] = {
    Criticality.VERY_LOW: 0.2,
    Criticality.LOW: 0.4,
    Criticality.MEDIUM: 0.6,
    Criticality.HIGH: 0.8,
    Criticality.CRITICAL: 1.0,
}


def risk_band_from_score(score: float) -> RiskBand:
    """Map a normalized 0–100 risk score to a risk band."""
    if score <= 20:
        return RiskBand.VERY_LOW
    if score <= 40:
        return RiskBand.LOW
    if score <= 60:
        return RiskBand.MEDIUM
    if score <= 80:
        return RiskBand.HIGH
    return RiskBand.CRITICAL
