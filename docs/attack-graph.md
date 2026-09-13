# Attack Graph Methodology (Review 1)

## Goal

Build an **analytical** attack graph from the Digital Twin and discover possible paths between source and target assets.

This is **not** real-world exploitation.

## Graph construction (NetworkX `DiGraph`)

### Nodes

From twin assets:

- `asset_id`, name, type, layer
- criticality
- compromise_state (foundation field; default `UNCOMPROMISED`)
- open vulnerability count

### Edges

From twin relationships:

- relationship type / trust
- protocol / port metadata (via relationship)
- associated synthetic vulnerability (best open vuln on endpoints)
- `attack_stage` heuristic
- local `edge_risk` estimate

## Path discovery

Uses `networkx.all_simple_paths` with configurable max length.

Demo scenario source/target pairs are **hints for which queries to run**, not hard-coded path strings:

- Scenario A: Patient Monitoring Device → Cloud Application Server
- Scenario B: IoT Gateway → Patient Database
- Scenario C: Doctor → Patient Database

If the topology changes and connectivity is removed, paths disappear.

## APIs

- `GET /api/attack-graph`
- `GET /api/attack-paths?source_asset_id=&target_asset_id=&max_paths=&max_length=`

## Future (not in Review 1)

Probabilistic propagation, timed simulation, and multi-stage exploit modeling belong to later reviews.
