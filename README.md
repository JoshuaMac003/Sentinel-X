# SENTINEL-X

**Digital Twin-Based Predictive Cyber Risk Forecasting and Attack Simulation Platform for Cloud Environments**

> Demonstration data is entirely **synthetic**. The platform does not connect to, scan, or exploit real hospital systems. All risk scores are **rule-based and explainable**. All attack simulations are **synthetic graph traversal only** — no real exploitation occurs.

---

## Reviews

| Review | Theme | Status |
|--------|-------|--------|
| R1 | MODEL + ANALYZE — Digital Twin, Attack Graph, Baseline Risk | ✅ Complete |
| R2 | SIMULATE — Scenario Engine, Blast Radius, Risk Comparison | ✅ Complete |
| R3 | PREDICT — ML Forecasting, NL Analyst | 🔜 Planned |
| R4 | RESPOND — SDN Automated Response | 🔜 Planned |
| R5 | EVALUATE — Benchmarking & Reporting | 🔜 Planned |

---

## Features

### Review 1 — MODEL + ANALYZE

- Asset / relationship / vulnerability modeling (SQLAlchemy + Alembic)
- Deterministic Smart Hospital seed dataset (16 assets, 23 relationships, 16 vulnerabilities)
- Dynamic Digital Twin snapshots with live topology
- NetworkX attack graph + analytical path discovery
- Explainable baseline cyber-risk (0–100) with per-factor breakdown
- FastAPI REST API + OpenAPI docs (`/docs`)
- React + TypeScript + Vite + Tailwind dashboard
- Interactive topology via React Flow

### Review 2 — SIMULATE

- **Scenario-based attack simulation** — 4 pre-seeded hospital scenarios (SCEN-A/B/C/D)
- **Ad-hoc simulations** — custom source + target asset selection
- **Multi-hop path propagation** — vulnerability-gated lateral movement engine
- **BLOCKED vs SUCCESS outcomes** — simulation halts when target has no open vulnerability
- **Blast radius analysis** — affected zones, criticality distribution, per-asset impact scores
- **Risk delta overlay** — compares baseline risk vs. post-simulation risk per asset
- **Full event timeline** — each hop recorded with timestamp, reason, and CVE context
- **Simulation history** — all past runs stored and inspectable in the UI
- **Interactive topology canvas** — compromised/path/target/blocked nodes rendered distinctly

---

## Prerequisites

- Python **3.11** (`py -3.11` on Windows)
- Node.js **20+**
- Optional: Docker Desktop for PostgreSQL

---

## Quick Start

### 1. Backend

```bash
cd backend
py -3.11 -m venv .venv

# Windows
.venv\Scripts\activate

pip install -r requirements.txt
cd ..
copy .env.example .env   # optional — defaults to SQLite

cd backend
py -3.11 -m seed.run_seed
py -3.11 -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- API docs: http://127.0.0.1:8000/docs
- Health: http://127.0.0.1:8000/api/health
- Reseed via API: `POST /api/admin/seed`

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://127.0.0.1:5173  
Vite proxies `/api` → `http://127.0.0.1:8000`.

**Navigation:**
- **Dashboard** — topology, risk overview, attack paths
- **Attack Simulation** — run scenarios or ad-hoc simulations, inspect results

### PostgreSQL (optional)

```bash
docker compose up -d
# Set DATABASE_URL=postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel_x
```

---

## Tests

```bash
cd backend
py -3.11 -m pytest tests -v
# Expected: 14 passed (7 Review 1 + 7 Review 2)
```

```bash
cd frontend
npm run typecheck
npm run build
# Expected: Clean build, 0 TypeScript errors
```

---

## Review 2 Demo Flow

1. Start backend + reseed: `py -3.11 -m seed.run_seed`
2. Start frontend: `npm run dev`
3. Navigate to **Attack Simulation** in the sidebar
4. Select **SCEN-A** (IoT pivot to records DB) → **Run Simulation** → expect `SUCCESS`
5. Select **SCEN-D** (blocked by closed CVE) → **Run Simulation** → expect `BLOCKED`
6. View **Blast Radius** — affected assets, criticality breakdown
7. View **Risk Comparison** — baseline vs. post-simulation risk delta
8. View **Event Timeline** — per-hop propagation log
9. Try **ad-hoc simulation** — pick any source/target from dropdowns
10. Click **Inspect** on any past simulation in the history table

---

## API Surface

### Review 1

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/admin/seed` | Reset + seed Smart Hospital |
| GET/POST/PUT/DELETE | `/api/assets` | Asset CRUD |
| GET/POST | `/api/relationships` | Relationships |
| GET/POST/PUT | `/api/vulnerabilities` | Vulnerabilities |
| GET | `/api/digital-twin` | Twin snapshot |
| GET | `/api/digital-twin/topology` | Topology graph |
| GET | `/api/attack-graph` | Attack graph nodes/edges |
| GET | `/api/attack-paths` | Discovered attack paths |
| GET | `/api/risk/overview` | Baseline risk overview |
| GET | `/api/risk/assets` | Per-asset risk scores |
| GET | `/api/risk/paths` | Per-path risk scores |

### Review 2

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/scenarios` | List all attack scenarios |
| GET | `/api/scenarios/{id}` | Get scenario details |
| POST | `/api/simulations` | Run a new simulation |
| GET | `/api/simulations` | Simulation history |
| GET | `/api/simulations/{id}` | Simulation detail |
| GET | `/api/simulations/{id}/events` | Hop-by-hop event timeline |
| GET | `/api/simulations/{id}/impact` | Blast radius + impact scores |
| GET | `/api/simulations/{id}/risk-comparison` | Baseline vs. sim risk delta |
| GET | `/api/risk/comparison` | Risk comparison (optional sim_id param) |

---

## Pre-Seeded Attack Scenarios

| ID | Name | Source | Target | Expected Result |
|----|------|--------|--------|-----------------|
| SCEN-A | IoT Pivot to Records | iot_gateway_01 | medical_records_db | SUCCESS |
| SCEN-B | Admin Workstation to EHR | admin_workstation | ehr_application | SUCCESS |
| SCEN-C | PACS Lateral to Pharma | pacs_system | pharmacy_system | SUCCESS |
| SCEN-D | ICU Monitor to Records (Blocked) | icu_monitor_hub | medical_records_db | BLOCKED |

---

## Documentation

- [Architecture](docs/architecture.md)
- [Digital Twin](docs/digital-twin.md)
- [Attack Graph](docs/attack-graph.md)
- [Risk Model](docs/risk-model.md)
- [Attack Simulation](docs/attack-simulation.md)
- [Review 1 Report](docs/review-1.md)
- [Review 2 Report](docs/review-2.md)
