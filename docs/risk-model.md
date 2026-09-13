# Baseline Risk Model (Review 1)

## Important disclaimer

This is an **explainable rule-based baseline**.

It is **not** machine-learning predictive forecasting.
No accuracy metrics are claimed.

## Score range and bands

Scores are normalized to **0–100**:

| Score | Band |
|------:|------|
| 0–20 | VERY_LOW |
| 21–40 | LOW |
| 41–60 | MEDIUM |
| 61–80 | HIGH |
| 81–100 | CRITICAL |

## Configurable weights (asset model)

From environment / settings (normalized to sum 1):

- `RISK_WEIGHT_SEVERITY` (default 0.35)
- `RISK_WEIGHT_EXPLOITABILITY` (default 0.25)
- `RISK_WEIGHT_CRITICALITY` (default 0.25)
- `RISK_WEIGHT_PATH` (default 0.15)

### Asset formula

For each asset:

1. **severity_cvss** = `0.6 * mean(severity_score) + 0.4 * mean(cvss/10)` over open vulns  
   (or 0.05 if none)
2. **exploitability** = mean exploitability score of open vulns (or 0.05)
3. **criticality** = mapped criticality score (1→0.2 … 5→1.0)
4. **path_exposure_trust** = blend of path frequency exposure and trust-level exposure

Each factor is returned with:

- `value` (0–1 input)
- `weight`
- `weighted_contribution` (0–1)
- `contribution` (points toward the 0–100 score)
- `detail` (human-readable rationale)

\[
risk_{asset} = \sum_i contribution_i
\]

where `contribution_i = value_i × weight_i × 100`.

## Path formula

Path risk blends:

- average node risk on the path (0.45)
- length pressure (shorter paths score higher) (0.20)
- stage depth (0.15)
- transition vulnerability density (0.20)

## Overall risk

Mean of assessed asset baseline scores.

## Model version

`baseline-v1`

Future predictive engines should compare against this baseline rather than replace its explainability.
