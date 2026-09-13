import { useMemo, useState } from "react";
import { api } from "../services/api";
import { useAsync } from "../hooks/useAsync";
import { criticalityLabel } from "../utils/style";
import { EmptyState, ErrorState, LoadingState } from "../components/ui";

export function AssetsPage() {
  const assets = useAsync(() => api.assets(), []);
  const risk = useAsync(() => api.riskAssets(), []);
  const [query, setQuery] = useState("");
  const [layer, setLayer] = useState("ALL");

  const riskMap = useMemo(() => {
    const map = new Map<string, { score: number; band: string }>();
    for (const item of risk.data ?? []) {
      map.set(item.asset_id, { score: item.risk_score, band: item.risk_band });
    }
    return map;
  }, [risk.data]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (assets.data ?? []).filter((asset) => {
      const matchesLayer = layer === "ALL" || asset.layer === layer;
      const matchesQuery =
        !q ||
        asset.asset_name.toLowerCase().includes(q) ||
        asset.asset_type.toLowerCase().includes(q) ||
        (asset.ip_address ?? "").toLowerCase().includes(q);
      return matchesLayer && matchesQuery;
    });
  }, [assets.data, query, layer]);

  if (assets.loading || risk.loading) return <LoadingState label="Loading assets…" />;
  if (assets.error || !assets.data) {
    return <ErrorState message={assets.error ?? "Assets unavailable"} onRetry={assets.reload} />;
  }

  const layers = Array.from(new Set(assets.data.map((a) => a.layer))).sort();

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search assets…"
          className="min-w-[220px] flex-1 rounded-lg border border-[var(--border)] bg-[var(--bg-elevated)] px-3 py-2 text-sm"
        />
        <select
          value={layer}
          onChange={(e) => setLayer(e.target.value)}
          className="rounded-lg border border-[var(--border)] bg-[var(--bg-elevated)] px-3 py-2 text-sm"
        >
          <option value="ALL">All layers</option>
          {layers.map((l) => (
            <option key={l} value={l}>
              {l}
            </option>
          ))}
        </select>
      </div>

      {filtered.length === 0 ? (
        <EmptyState message="No assets match the current filters." />
      ) : (
        <div className="panel overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="border-b border-[var(--border)] text-xs uppercase tracking-wide text-[var(--muted)]">
              <tr>
                <th className="px-4 py-3">Asset</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Layer</th>
                <th className="px-4 py-3">Criticality</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Services</th>
                <th className="px-4 py-3">Risk</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((asset) => {
                const r = riskMap.get(asset.asset_id);
                return (
                  <tr key={asset.asset_id} className="border-b border-[var(--border)]/70">
                    <td className="px-4 py-3">
                      <div className="font-medium">{asset.asset_name}</div>
                      <div className="mono text-xs text-[var(--muted)]">{asset.ip_address ?? "—"}</div>
                    </td>
                    <td className="px-4 py-3">{asset.asset_type}</td>
                    <td className="px-4 py-3">{asset.layer}</td>
                    <td className="px-4 py-3">
                      {asset.criticality} · {criticalityLabel(asset.criticality)}
                    </td>
                    <td className="px-4 py-3">{asset.status}</td>
                    <td className="px-4 py-3">{asset.services.length}</td>
                    <td className="px-4 py-3 mono">
                      {r ? `${r.score} (${r.band})` : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
