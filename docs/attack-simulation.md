# SENTINEL-X — Digital Twin Attack Simulation Engine (Review 2)

## 1. Overview & Research Scope

The **SENTINEL-X Attack Simulation Engine** enables controlled, deterministic graph-based attack simulation over the Security-Aware Digital Twin.

It transforms static infrastructure topology and vulnerability findings into an active analytical laboratory to evaluate attack propagation, compromise progression, blast radius, and dynamic cyber risk.

> [!IMPORTANT]
> **Safety Guardrails & Academic Scope**
> - Operates **100% on synthetic graph state** within the Digital Twin database.
> - **Zero real network activity**: No port scanning, packet injection, payload execution, or real exploitation.
> - **Zero real PHI**: Synthetic hospital IoT and cloud infrastructure only.
> - **Rule-based & Deterministic**: Reproducible graph traversal rules without non-deterministic randomness.

---

## 2. Attack Simulation Architecture

```text
Database State (Assets, Relationships, Synthetic Vulns)
                        ↓
             Digital Twin Service
                        ↓
            NetworkX Attack Graph
                        ↓
    Attack Scenario / Ad-Hoc Payload Target
                        ↓
            Simulation Engine Traversal
 ┌──────────────────────┼──────────────────────┐
 ↓                      ↓                      ↓
Hop Rules Evaluation   Event Timeline      Compromise State
 ↓                      ↓                      ↓
Target / Block       Impact Metrics       Risk Overlay
```

---

## 3. Formal Attack Scenarios

SENTINEL-X includes pre-configured analytical scenarios reflecting realistic cloud-IoT attack vectors:

| Scenario Code | Scenario Name | Source Asset | Target Asset | Attack Vector | Expected Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SCEN-A` | Medical IoT to Cloud App | Patient Monitoring Device | Cloud Application Server | Lateral Movement over MQTT/HTTPS | **SUCCESS** |
| `SCEN-B` | Gateway to Patient Database | IoT Gateway | Patient Database | Multi-hop Perimeter Breach | **SUCCESS** |
| `SCEN-C` | Doctor Portal Account Breach | Doctor (User Identity) | Patient Database | Credential Access / IdP Delegation | **SUCCESS** |
| `SCEN-D` | Sensor to Medical Records DB | Medical Sensor | Medical Records Database | Defensive Trust / Remediated Target | **BLOCKED** |

---

## 4. Propagation Rules

For each step $u \to v$ in the Digital Twin graph, the engine evaluates:

1. **Edge Reachability**: Directed relationship edge $u \to v$ exists in the graph.
2. **Initial Access**: Source node $u$ must possess an open synthetic vulnerability ($v_{open} \neq \emptyset$).
3. **Target Vulnerability**: Target node $v$ must possess an open synthetic finding (or belong to a direct host/management delegation edge). If target finding is `CLOSED` or `MITIGATED`, propagation is **BLOCKED**.
4. **Trust Boundary Enforcement**: Relationships with `UNTRUSTED` trust levels require $HIGH+$ exploitability on either endpoint.
5. **Minimum Exploitability**: Vulnerability exploitability score must meet or exceed configured simulation minimum.

---

## 5. Event Model & Provenance

Every simulation step records structured provenance events (`SimulationEvent`):

- `step_number`: Sequential step index.
- `source_asset_id` & `target_asset_id`: Transition endpoints.
- `action`: `VALIDATE`, `INITIAL_ACCESS`, `PROPAGATE`, `BLOCK`, `TARGET_REACHED`.
- `previous_state` $\to$ `new_state`: Transition overlay (`NORMAL` $\to$ `COMPROMISED`).
- `vulnerability_identifier`: Synthetic finding identifier enabling transition (e.g. `SYN-AUTH-002`).
- `reason`: Explainable natural language explanation.

---

## 6. Analytical Blast Radius & Impact Engine

Analytical blast radius is computed using graph descendants and node criticality:

$$\text{Impact Score} = \min\left(100, 100 \times \left(0.30 \frac{C_{comp}}{N_{total}} + 0.25 \frac{C_{crit\_reach}}{N_{crit\_total}} + 0.20 \frac{C_{sens\_reach}}{N_{sens\_total}} + 0.15 \frac{\min(d_{prop}, 6)}{6} + 0.10 \frac{\text{BlastRadius}}{100}\right)\right)$$

Where:
- $C_{comp}$: Compromised assets in run
- $C_{crit\_reach}$: Criticality 5 assets reached
- $C_{sens\_reach}$: Data layer / database assets reached
- $d_{prop}$: Maximum propagation hop depth

---

## 7. Baseline vs. Simulation Risk Overlay

Review 1 baseline risk remains unchanged as the authoritative baseline inventory metric. Simulation risk overlays run impact without mutating baseline database storage:

$$\text{Simulation Risk} = w_{base} \times \text{Risk}_{baseline} + w_{impact} \times \text{Impact Score}$$

The UI displays exact score changes ($\Delta$) and factor attribution for presentation clarity.
