# Digital Twin Model (Review 1)

## What is modeled

The Digital Twin is a **virtual representation** of the synthetic Smart Hospital infrastructure reconstructed on demand from database entities:

- Assets (type, layer, IP, OS, status)
- Criticality and trust level
- Services
- Vulnerabilities (synthetic)
- Relationships / connectivity
- Derived security state

## Construction

`DigitalTwinService.build_snapshot()`:

1. Loads assets with services and vulnerabilities
2. Loads relationships
3. Maps entities into twin nodes/edges
4. Groups assets into topology layers
5. Derives `security_state` from status + open vulnerabilities

The twin is **not** a static JSON file. Changing assets via API changes the next twin snapshot.

## Security state rules

| Condition | State |
|-----------|-------|
| Asset status `COMPROMISED` | `COMPROMISED` |
| Open HIGH/CRITICAL vulns | `AT_RISK` |
| Other open vulns | `DEGRADED` |
| No open vulns | `HARDENED` |

## APIs

- `GET /api/digital-twin` — full snapshot
- `GET /api/digital-twin/topology` — nodes, edges, layers

## Assumptions

- Connectivity is explicit via the relationships table
- Twin fidelity is limited to Review 1 schema (no live telemetry)
- All hospital/IoT content is fictional
