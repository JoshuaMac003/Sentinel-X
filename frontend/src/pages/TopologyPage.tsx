import { useState } from "react";
import { api } from "../services/api";
import { useAsync } from "../hooks/useAsync";
import { TopologyCanvas } from "../components/TopologyCanvas";
import { EmptyState, ErrorState, LoadingState } from "../components/ui";

export function TopologyPage() {
  const twin = useAsync(() => api.digitalTwin(), []);
  const [seeding, setSeeding] = useState(false);
  const [seedMessage, setSeedMessage] = useState<string | null>(null);

  async function handleSeed() {
    setSeeding(true);
    setSeedMessage(null);
    try {
      const result = await api.seed();
      setSeedMessage(
        `${result.message}: ${result.assets} assets, ${result.relationships} relationships, ${result.vulnerabilities} vulnerabilities`,
      );
      twin.reload();
    } catch (err) {
      setSeedMessage(err instanceof Error ? err.message : "Seed failed");
    } finally {
      setSeeding(false);
    }
  }

  if (twin.loading) return <LoadingState label="Constructing Digital Twin…" />;
  if (twin.error || !twin.data) {
    return <ErrorState message={twin.error ?? "Twin unavailable"} onRetry={twin.reload} />;
  }

  if (twin.data.asset_count === 0) {
    return (
      <div className="space-y-4">
        <EmptyState message="No infrastructure in the Digital Twin yet." />
        <button
          type="button"
          disabled={seeding}
          onClick={handleSeed}
          className="rounded-lg bg-[var(--accent)] px-4 py-2 text-sm text-white disabled:opacity-60"
        >
          {seeding ? "Seeding…" : "Seed Smart Hospital Dataset"}
        </button>
        {seedMessage ? <p className="text-sm text-[var(--muted)]">{seedMessage}</p> : null}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold">Digital Twin Topology</h2>
          <p className="text-sm text-[var(--muted)]">
            {twin.data.environment} · generated {new Date(twin.data.generated_at).toLocaleString()}
          </p>
        </div>
        <button
          type="button"
          disabled={seeding}
          onClick={handleSeed}
          className="rounded-lg border border-[var(--border)] px-3 py-2 text-sm hover:bg-[var(--bg-panel)] disabled:opacity-60"
        >
          {seeding ? "Reseeding…" : "Reset & Reseed"}
        </button>
      </div>
      <TopologyCanvas twin={twin.data} />
      <p className="text-xs text-[var(--muted)]">{twin.data.notes.join(" ")}</p>
      {seedMessage ? <p className="text-sm text-[var(--accent)]">{seedMessage}</p> : null}
    </div>
  );
}
