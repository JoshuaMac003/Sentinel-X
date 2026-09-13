# Review 1 Implementation Report

## Scope implemented

| Capability | Status |
|------------|--------|
| FastAPI backend + SQLAlchemy models | Done |
| SQLite + PostgreSQL support | Done |
| Smart Hospital synthetic seed | Done |
| Asset / relationship / vulnerability APIs | Done |
| Digital Twin from DB | Done |
| NetworkX attack graph + path discovery | Done |
| Explainable baseline risk (0–100) | Done |
| React + TS + Vite + Tailwind dashboard | Done |
| React Flow topology | Done |
| Tests + documentation | Done |

## Explicitly out of scope

- ML predictive cyber-risk forecasting
- Natural-language security analyst
- SDN automated response
- Real exploitation / scanning
- Real hospital deployment
- Fabricated evaluation metrics

## Demonstration dataset

- 16 assets across IoT, edge, network, cloud, application, data, user layers
- 23 relationships (including Auth → Cloud analytical trust edge for Scenario C)
- 16 synthetic vulnerabilities (`SYN-*`)
- Deterministic IDs for reproducible reseeding

## Verification results (local)

- Backend pytest: **7 passed**
- E2E script (`scripts/e2e_verify.py`): **E2E_OK**
- Frontend `npm run typecheck` + `npm run build`: **passed**
- Alembic: `0001_initial` applied

## Academic integrity checks

- No real patient data
- No invented CVE IDs
- No claim of ML prediction in Review 1
- Attack paths computed dynamically from topology
- Dashboard consumes live API data
