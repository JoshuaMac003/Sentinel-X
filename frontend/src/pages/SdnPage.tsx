
import { useCallback, useEffect, useState } from "react";
import { api } from "../services/api";
import type { SdnMonitorResponse, SdnPort } from "../types";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function StatCard({
  label,
  value,
  description,
}: {
  label: string;
  value: string | number;
  description: string;
}) {
  return (
    <div className="panel p-5">
      <p className="text-sm text-[var(--muted)]">{label}</p>
      <p className="mt-2 text-3xl font-semibold">{value}</p>
      <p className="mt-1 text-xs text-[var(--muted)]">{description}</p>
    </div>
  );
}

export function SdnPage() {
  const [data, setData] = useState<SdnMonitorResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const loadData = useCallback(async () => {
    try {
      const result = await api.sdnMonitor();
      setData(result);
      setError("");
      setLastUpdated(new Date());
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unable to retrieve SDN statistics."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();

    const interval = window.setInterval(() => {
      void loadData();
    }, 5000);

    return () => window.clearInterval(interval);
  }, [loadData]);

  const switches = data?.switches ?? [];
  const connectedSwitches = switches.filter(
    (sw) => sw.connection === "connected"
  );

  const ports: (SdnPort & { switch_id: number })[] =
    connectedSwitches.flatMap((sw) =>
      sw.ports
        .filter((port) => port.port !== 4294967294)
        .map((port) => ({ ...port, switch_id: sw.switch_id }))
    );

  const totalRxPackets = ports.reduce(
    (sum, port) => sum + port.rx_packets,
    0
  );

  const totalTxPackets = ports.reduce(
    (sum, port) => sum + port.tx_packets,
    0
  );

  const totalRxBytes = ports.reduce(
    (sum, port) => sum + port.rx_bytes,
    0
  );

  const totalTxBytes = ports.reduce(
    (sum, port) => sum + port.tx_bytes,
    0
  );

  const totalErrors = ports.reduce(
    (sum, port) => sum + port.rx_errors + port.tx_errors,
    0
  );

  if (loading && !data) {
    return (
      <div className="panel p-6">
        <p className="text-[var(--muted)]">
          Connecting to the SDN monitoring service...
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <section className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-semibold">SDN Network Monitoring</h2>
          <p className="mt-1 text-sm text-[var(--muted)]">
            Live network statistics collected through the OS-Ken controller.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <span
            className={`rounded-full px-3 py-1 text-xs font-medium ${
              error
                ? "bg-red-500/15 text-red-400"
                : "bg-emerald-500/15 text-emerald-400"
            }`}
          >
            {error ? "Connection issue" : "Monitoring active"}
          </span>

          <button
            onClick={() => void loadData()}
            className="rounded-lg border border-[var(--border)] px-4 py-2 text-sm hover:bg-[var(--bg-panel)]"
          >
            Refresh
          </button>
        </div>
      </section>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300">
          {error}
          <p className="mt-1 text-xs">
            Check that FastAPI, OS-Ken and Mininet are running.
          </p>
        </div>
      )}

      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        <StatCard
          label="Connected Switches"
          value={connectedSwitches.length}
          description="Active OpenFlow switches"
        />

        <StatCard
          label="Active Ports"
          value={ports.length}
          description="Physical switch ports"
        />

        <StatCard
          label="Received Packets"
          value={totalRxPackets.toLocaleString()}
          description="Cumulative RX packets"
        />

        <StatCard
          label="Transmitted Packets"
          value={totalTxPackets.toLocaleString()}
          description="Cumulative TX packets"
        />

        <StatCard
          label="Received Traffic"
          value={formatBytes(totalRxBytes)}
          description="Cumulative RX bytes"
        />

        <StatCard
          label="Network Errors"
          value={totalErrors}
          description="RX and TX errors"
        />
      </section>

      <section className="panel overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] p-5">
          <div>
            <h3 className="text-lg font-semibold">Connected Switches</h3>
            <p className="mt-1 text-xs text-[var(--muted)]">
              OpenFlow controller connection status
            </p>
          </div>

          <span className="mono text-xs text-[var(--muted)]">
            {lastUpdated
              ? `Updated ${lastUpdated.toLocaleTimeString()}`
              : "Waiting for data"}
          </span>
        </div>

        {connectedSwitches.length === 0 ? (
          <p className="p-5 text-sm text-[var(--muted)]">
            No connected switches found.
          </p>
        ) : (
          connectedSwitches.map((sw) => (
            <div
              key={sw.switch_id}
              className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] p-5 last:border-0"
            >
              <div>
                <p className="font-medium">Switch {sw.switch_id}</p>
                <p className="mt-1 text-xs text-[var(--muted)]">
                  {sw.ports.filter(
                    (port) => port.port !== 4294967294
                  ).length}{" "}
                  physical ports detected
                </p>
              </div>

              <span className="rounded-full bg-emerald-500/15 px-3 py-1 text-xs text-emerald-400">
                Connected
              </span>
            </div>
          ))
        )}
      </section>

      <section className="panel overflow-hidden">
        <div className="border-b border-[var(--border)] p-5">
          <h3 className="text-lg font-semibold">Port Statistics</h3>
          <p className="mt-1 text-xs text-[var(--muted)]">
            Live counters reported by Open vSwitch
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-[var(--bg-elevated)] text-xs text-[var(--muted)]">
              <tr>
                <th className="px-5 py-3">Switch</th>
                <th className="px-5 py-3">Port</th>
                <th className="px-5 py-3">RX Packets</th>
                <th className="px-5 py-3">TX Packets</th>
                <th className="px-5 py-3">RX Bytes</th>
                <th className="px-5 py-3">TX Bytes</th>
                <th className="px-5 py-3">Errors</th>
              </tr>
            </thead>

            <tbody>
              {ports.map((port) => (
                <tr
                  key={`${port.switch_id}-${port.port}`}
                  className="border-t border-[var(--border)]"
                >
                  <td className="px-5 py-4">s{port.switch_id}</td>
                  <td className="px-5 py-4 mono">
                    s{port.switch_id}-eth{port.port}
                  </td>
                  <td className="px-5 py-4 mono">
                    {port.rx_packets.toLocaleString()}
                  </td>
                  <td className="px-5 py-4 mono">
                    {port.tx_packets.toLocaleString()}
                  </td>
                  <td className="px-5 py-4 mono">
                    {formatBytes(port.rx_bytes)}
                  </td>
                  <td className="px-5 py-4 mono">
                    {formatBytes(port.tx_bytes)}
                  </td>
                  <td className="px-5 py-4">
                    <span
                      className={
                        port.rx_errors + port.tx_errors > 0
                          ? "text-red-400"
                          : "text-emerald-400"
                      }
                    >
                      {port.rx_errors + port.tx_errors}
                    </span>
                  </td>
                </tr>
              ))}

              {ports.length === 0 && (
                <tr>
                  <td
                    colSpan={7}
                    className="px-5 py-8 text-center text-[var(--muted)]"
                  >
                    No port statistics available.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel p-5">
        <h3 className="font-semibold">Network Traffic Summary</h3>
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <div>
            <p className="text-sm text-[var(--muted)]">
              Total received data
            </p>
            <p className="mt-1 text-2xl font-semibold">
              {formatBytes(totalRxBytes)}
            </p>
          </div>
          <div>
            <p className="text-sm text-[var(--muted)]">
              Total transmitted data
            </p>
            <p className="mt-1 text-2xl font-semibold">
              {formatBytes(totalTxBytes)}
            </p>
          </div>
        </div>
        <p className="mt-4 text-xs text-[var(--muted)]">
          Counters are cumulative Open vSwitch statistics, not instantaneous
          bandwidth measurements.
        </p>
      </section>
    </div>
  );
}
