# SENTINEL-X System Architecture (Review 1)

## Purpose

SENTINEL-X models a **synthetic Smart Hospital Cloud–IoT environment** as a Digital Twin, derives analytical attack graphs, discovers potential attack paths, and computes an **explainable baseline cyber-risk score**.

Review 1 implements **MODEL → ANALYZE**. Predictive ML forecasting, SDN response, and experimental evaluation are deferred.

## High-level data flow

```text
SQLite / PostgreSQL
        ↓
SQLAlchemy models
        ↓
Service layer (assets, relationships, vulnerabilities)
        ↓
Digital Twin engine  →  live virtual infrastructure snapshot
        ↓
Attack Graph engine (NetworkX)  →  nodes/edges + path discovery
        ↓
Baseline Risk engine  →  explainable 0–100 scores + factors
        ↓
FastAPI REST API
        ↓
React dashboard (React Flow topology)
```

## Backend modules

| Module | Responsibility |
|--------|----------------|
| `app/api` | HTTP routing, validation, status codes |
| `app/services` | CRUD orchestration |
| `app/models` | Relational persistence |
| `app/digital_twin` | Dynamic twin construction |
| `app/attack_graph` | NetworkX graph + path discovery |
| `app/risk` | Rule-based baseline risk |
| `seed/` | Deterministic Smart Hospital dataset |

Business logic is not embedded in route handlers.

## Frontend modules

| Area | Responsibility |
|------|----------------|
| `pages/` | Overview, Twin, Assets, Vulns, Paths, Risk |
| `components/TopologyCanvas.tsx` | React Flow interactive topology |
| `services/api.ts` | Typed API client |
| `hooks/useAsync.ts` | Loading / error / reload |

## Extension points (not implemented)

- Review 2: attack simulation / propagation
- Review 3: predictive risk forecasting + NL analyst
- Review 4: SDN mitigation
- Review 5: evaluation & benchmarking

## Security posture

- Synthetic data only
- No real hospital connectivity
- No exploitation tooling
- No invented CVE identifiers (`SYN-*` labels)
