import { useMemo, useState } from "react";
import { api } from "../services/api";
import { useAsync } from "../hooks/useAsync";
import { EmptyState, ErrorState, LoadingState } from "../components/ui";

export function VulnerabilitiesPage() {
  const vulns = useAsync(() => api.vulnerabilities(), []);
  const assets = useAsync(() => api.assets(), []);
  const [severity, setSeverity] = useState("ALL");

  const assetNames = useMemo(() => {
    const map = new Map<string, string>();
    for (const asset of assets.data ?? []) map.set(asset.asset_id, asset.asset_name);
    return map;
  }, [assets.data]);

  const filtered = useMemo(() => {
    return (vulns.data ?? []).filter((v) => severity === "ALL" || v.severity === severity);
  }, [vulns.data, severity]);

  if (vulns.loading || assets.loading) return <LoadingState label="Loading vulnerabilities…" />;
  if (vulns.error || !vulns.data) {
    return <ErrorState message={vulns.error ?? "Vulnerabilities unavailable"} onRetry={vulns.reload} />;
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-[var(--muted)]">
          All findings are synthetic demonstration records (SYN-* identifiers). No real CVEs invented.
        </p>
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="rounded-lg border border-[var(--border)] bg-[var(--bg-elevated)] px-3 py-2 text-sm"
        >
          <option value="ALL">All severities</option>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW", "VERY_LOW"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>

      {filtered.length === 0 ? (
        <EmptyState message="No vulnerabilities for this filter." />
      ) : (
        <div className="panel overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="border-b border-[var(--border)] text-xs uppercase tracking-wide text-[var(--muted)]">
              <tr>
                <th className="px-4 py-3">Identifier</th>
                <th className="px-4 py-3">Vulnerability</th>
                <th className="px-4 py-3">Asset</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">CVSS</th>
                <th className="px-4 py-3">Exploitability</th>
                <th className="px-4 py-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((v) => (
                <tr key={v.vulnerability_id} className="border-b border-[var(--border)]/70 align-top">
                  <td className="px-4 py-3 mono text-xs">{v.identifier}</td>
                  <td className="px-4 py-3">
                    <div className="font-medium">{v.name}</div>
                    <div className="mt-1 max-w-md text-xs text-[var(--muted)]">{v.remediation}</div>
                  </td>
                  <td className="px-4 py-3">{assetNames.get(v.asset_id) ?? v.asset_id}</td>
                  <td className="px-4 py-3">{v.severity}</td>
                  <td className="px-4 py-3 mono">{v.cvss_score.toFixed(1)}</td>
                  <td className="px-4 py-3">{v.exploitability}</td>
                  <td className="px-4 py-3">{v.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
