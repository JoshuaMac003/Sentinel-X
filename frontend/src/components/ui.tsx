export function StatCard({
  label,
  value,
  hint,
}: {
  label: string;
  value: string | number;
  hint?: string;
}) {
  return (
    <div className="panel p-4">
      <p className="text-xs uppercase tracking-[0.14em] text-[var(--muted)]">{label}</p>
      <p className="mt-2 text-3xl font-semibold tabular-nums">{value}</p>
      {hint ? <p className="mt-1 text-xs text-[var(--muted)]">{hint}</p> : null}
    </div>
  );
}

export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="panel flex min-h-40 items-center justify-center p-6 text-[var(--muted)]">
      {label}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="panel border-[var(--danger)] p-6">
      <p className="font-medium text-[var(--danger)]">Unable to load data</p>
      <p className="mt-2 text-sm text-[var(--muted)]">{message}</p>
      {onRetry ? (
        <button
          type="button"
          onClick={onRetry}
          className="mt-4 rounded-lg bg-[var(--accent)] px-3 py-2 text-sm text-white"
        >
          Retry
        </button>
      ) : null}
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="panel flex min-h-40 items-center justify-center p-6 text-sm text-[var(--muted)]">
      {message}
    </div>
  );
}

export function BandBadge({ band }: { band?: string | null }) {
  const color =
    band === "CRITICAL"
      ? "bg-[#c45c5c]"
      : band === "HIGH"
        ? "bg-[#c48a3a]"
        : band === "MEDIUM"
          ? "bg-[#c4a35a] text-black"
          : band === "LOW"
            ? "bg-[#3d7ea6]"
            : "bg-[#1f8a70]";
  return (
    <span className={`inline-flex rounded-md px-2 py-0.5 text-xs font-medium text-white ${color}`}>
      {band ?? "N/A"}
    </span>
  );
}
