import { api } from "../services/api";
import { useAsync } from "../hooks/useAsync";
import { BandBadge, EmptyState, ErrorState, LoadingState } from "../components/ui";

export function AttackPathsPage() {
  const paths = useAsync(() => api.attackPaths(), []);

  if (paths.loading) return <LoadingState label="Discovering attack paths…" />;
  if (paths.error || !paths.data) {
    return <ErrorState message={paths.error ?? "Attack paths unavailable"} onRetry={paths.reload} />;
  }
  if (paths.data.paths.length === 0) {
    return <EmptyState message="No attack paths discovered for the current topology." />;
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-[var(--muted)]">
        Paths are discovered dynamically with NetworkX from Digital Twin relationships. Analytical only —
        not real exploits.
      </p>
      <div className="space-y-3">
        {paths.data.paths.map((path) => (
          <article key={path.path_id} className="panel p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h3 className="font-semibold">
                  {path.scenario_label ?? `${path.source_name} → ${path.target_name}`}
                </h3>
                <p className="mt-1 mono text-xs text-[var(--muted)]">
                  {path.hops.map((h) => h.asset_name).join(" → ")}
                </p>
              </div>
              <div className="text-right">
                <BandBadge band={path.risk_band} />
                <p className="mono mt-1 text-sm">{path.risk_score ?? "—"}</p>
              </div>
            </div>
            <div className="mt-3 grid gap-2 text-sm text-[var(--muted)] md:grid-cols-3">
              <div>Stages: {path.stage_count}</div>
              <div>Length: {path.length}</div>
              <div>
                Vulns: {path.vulnerabilities_on_path.length ? path.vulnerabilities_on_path.join(", ") : "—"}
              </div>
            </div>
            <p className="mt-3 text-sm">{path.explanation}</p>
          </article>
        ))}
      </div>
    </div>
  );
}
