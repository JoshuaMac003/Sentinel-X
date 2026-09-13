import { Link } from "react-router-dom";
import { api } from "../services/api";
import { useAsync } from "../hooks/useAsync";
import { BandBadge, ErrorState, LoadingState, StatCard } from "../components/ui";

export function OverviewPage() {
  const risk = useAsync(() => api.riskOverview(), []);
  const twin = useAsync(() => api.digitalTwin(), []);
  const paths = useAsync(() => api.attackPaths(), []);

  if (risk.loading || twin.loading || paths.loading) {
    return <LoadingState label="Loading Smart Hospital overview…" />;
  }
  if (risk.error || twin.error || paths.error || !risk.data || !twin.data || !paths.data) {
    return (
      <ErrorState
        message={risk.error || twin.error || paths.error || "Unknown error"}
        onRetry={() => {
          risk.reload();
          twin.reload();
          paths.reload();
        }}
      />
    );
  }

  const highVulns = twin.data.assets.reduce(
    (acc, asset) =>
      acc +
      asset.vulnerabilities.filter((v) => v.severity === "HIGH" || v.severity === "CRITICAL").length,
    0,
  );

  return (
    <div className="space-y-6">
      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        <StatCard label="Total Assets" value={twin.data.asset_count} />
        <StatCard label="Critical Assets" value={twin.data.critical_asset_count} hint="Criticality = 5" />
        <StatCard label="Vulnerabilities" value={twin.data.vulnerability_count} hint="Synthetic SYN-*" />
        <StatCard label="High/Critical Vulns" value={highVulns} />
        <StatCard label="Attack Paths" value={paths.data.path_count} />
        <StatCard
          label="Overall Risk"
          value={risk.data.overall_risk_score}
          hint={risk.data.overall_risk_band}
        />
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <div className="panel p-5">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-lg font-semibold">Baseline Risk Snapshot</h2>
            <BandBadge band={risk.data.overall_risk_band} />
          </div>
          <p className="text-sm text-[var(--muted)]">{risk.data.explanation}</p>
          <div className="mt-4 grid grid-cols-2 gap-2 text-sm sm:grid-cols-5">
            {Object.entries(risk.data.distribution).map(([band, count]) => (
              <div key={band} className="rounded-lg border border-[var(--border)] p-2">
                <div className="text-xs text-[var(--muted)]">{band}</div>
                <div className="text-xl font-semibold">{count}</div>
              </div>
            ))}
          </div>
          <p className="mt-4 text-xs text-[var(--muted)]">{risk.data.notes.join(" ")}</p>
        </div>

        <div className="panel p-5">
          <h2 className="mb-3 text-lg font-semibold">High-Risk Assets</h2>
          {risk.data.high_risk_assets.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">No high/critical assets in current baseline.</p>
          ) : (
            <ul className="space-y-2">
              {risk.data.high_risk_assets.slice(0, 6).map((asset) => (
                <li
                  key={asset.asset_id}
                  className="flex items-center justify-between rounded-lg border border-[var(--border)] px-3 py-2"
                >
                  <span>{asset.asset_name}</span>
                  <span className="mono text-sm">
                    {asset.risk_score} <BandBadge band={asset.risk_band} />
                  </span>
                </li>
              ))}
            </ul>
          )}
          <Link to="/risk" className="mt-4 inline-block text-sm text-[var(--accent)]">
            Open risk analysis →
          </Link>
        </div>
      </section>

      <section className="panel p-5">
        <div className="mb-3 flex items-center justify-between gap-3">
          <h2 className="text-lg font-semibold">Priority Attack Paths</h2>
          <Link to="/topology" className="text-sm text-[var(--accent)]">
            View Digital Twin →
          </Link>
        </div>
        <div className="space-y-3">
          {paths.data.paths.slice(0, 4).map((path) => (
            <div key={path.path_id} className="rounded-lg border border-[var(--border)] p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="font-medium">
                  {path.scenario_label ?? `${path.source_name} → ${path.target_name}`}
                </p>
                <BandBadge band={path.risk_band} />
              </div>
              <p className="mt-1 mono text-xs text-[var(--muted)]">
                {path.hops.map((h) => h.asset_name).join(" → ")}
              </p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
