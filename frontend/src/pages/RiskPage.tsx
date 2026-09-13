import { api } from "../services/api";
import { useAsync } from "../hooks/useAsync";
import { BandBadge, ErrorState, LoadingState } from "../components/ui";

export function RiskPage() {
  const overview = useAsync(() => api.riskOverview(), []);
  const assets = useAsync(() => api.riskAssets(), []);
  const paths = useAsync(() => api.riskPaths(), []);

  if (overview.loading || assets.loading || paths.loading) {
    return <LoadingState label="Calculating baseline risk…" />;
  }
  if (overview.error || !overview.data) {
    return (
      <ErrorState
        message={overview.error ?? "Risk overview unavailable"}
        onRetry={() => {
          overview.reload();
          assets.reload();
          paths.reload();
        }}
      />
    );
  }

  return (
    <div className="space-y-6">
      <section className="panel p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-xl font-semibold">Baseline Cyber Risk</h2>
            <p className="text-sm text-[var(--muted)]">
              Model {overview.data.model_version} · explainable weighted factors · not predictive ML
            </p>
          </div>
          <div className="text-right">
            <div className="text-3xl font-semibold tabular-nums">{overview.data.overall_risk_score}</div>
            <BandBadge band={overview.data.overall_risk_band} />
          </div>
        </div>
        <p className="mt-4 text-sm">{overview.data.explanation}</p>
        <div className="mt-4 grid gap-3 md:grid-cols-2 lg:grid-cols-4">
          {overview.data.factors_summary.map((factor) => (
            <div key={factor.name} className="rounded-lg border border-[var(--border)] p-3">
              <div className="text-xs uppercase tracking-wide text-[var(--muted)]">{factor.name}</div>
              <div className="mono mt-1 text-lg">
                {(factor.contribution ?? factor.weight * 100).toFixed(1)} pts
              </div>
              <p className="mt-1 text-xs text-[var(--muted)]">
                weight {(factor.weight * 100).toFixed(0)}% · {factor.detail}
              </p>
            </div>
          ))}
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <div className="panel p-5">
          <h3 className="mb-3 text-lg font-semibold">Asset Prioritization</h3>
          <ul className="space-y-3">
            {(assets.data ?? []).slice(0, 8).map((asset) => (
              <li key={asset.asset_id} className="rounded-lg border border-[var(--border)] p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium">{asset.asset_name}</span>
                  <span className="mono text-sm">
                    {asset.risk_score} <BandBadge band={asset.risk_band} />
                  </span>
                </div>
                <p className="mt-2 text-xs text-[var(--muted)]">{asset.explanation}</p>
              </li>
            ))}
          </ul>
        </div>
        <div className="panel p-5">
          <h3 className="mb-3 text-lg font-semibold">High-Risk Paths</h3>
          <ul className="space-y-3">
            {(paths.data ?? []).slice(0, 8).map((path) => (
              <li key={path.path_id} className="rounded-lg border border-[var(--border)] p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium">
                    {path.scenario_label ?? `${path.source_name} → ${path.target_name}`}
                  </span>
                  <span className="mono text-sm">
                    {path.risk_score} <BandBadge band={path.risk_band} />
                  </span>
                </div>
                <p className="mono mt-1 text-xs text-[var(--muted)]">{path.path_display}</p>
                <p className="mt-2 text-xs text-[var(--muted)]">{path.explanation}</p>
              </li>
            ))}
          </ul>
        </div>
      </section>
    </div>
  );
}
