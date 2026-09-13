import { useState } from "react";
import { TopologyCanvas } from "../components/TopologyCanvas";
import { BandBadge, ErrorState, LoadingState, StatCard } from "../components/ui";
import { useAsync } from "../hooks/useAsync";
import { api } from "../services/api";
import type {
  Asset,
  DigitalTwin,
  Scenario,
  SimulationRun,
  SimulationSummary,
} from "../types";

export function SimulationPage() {
  const [twin, setTwin] = useState<DigitalTwin | null>(null);
  const [assetsList, setAssetsList] = useState<Asset[]>([]);
  const [scenariosList, setScenariosList] = useState<Scenario[]>([]);
  const [historyList, setHistoryList] = useState<SimulationSummary[]>([]);

  const [selectedScenarioId, setSelectedScenarioId] = useState<string>("");
  const [customSourceId, setCustomSourceId] = useState<string>("");
  const [customTargetId, setCustomTargetId] = useState<string>("");

  const [currentRun, setCurrentRun] = useState<SimulationRun | null>(null);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [simError, setSimError] = useState<string | null>(null);

  const twinAsync = useAsync(async () => {
    const [t, a, s, h] = await Promise.all([
      api.digitalTwin(),
      api.assets(),
      api.scenarios(),
      api.simulations(),
    ]);
    setTwin(t);
    setAssetsList(a);
    setScenariosList(s);
    setHistoryList(h);
    if (s.length > 0 && !selectedScenarioId) {
      setSelectedScenarioId(s[0].scenario_id);
    }
  }, []);

  const handleRunSimulation = async () => {
    setIsSimulating(true);
    setSimError(null);
    try {
      let run: SimulationRun;
      if (selectedScenarioId && selectedScenarioId !== "custom") {
        run = await api.runSimulation({ scenario_id: selectedScenarioId });
      } else {
        if (!customSourceId || !customTargetId) {
          throw new Error("Select both Source and Target assets for custom simulation");
        }
        run = await api.runSimulation({
          source_asset_id: customSourceId,
          target_asset_id: customTargetId,
        });
      }
      setCurrentRun(run);
      const updatedHistory = await api.simulations();
      setHistoryList(updatedHistory);
    } catch (err: unknown) {
      setSimError(err instanceof Error ? err.message : "Simulation execution failed");
    } finally {
      setIsSimulating(false);
    }
  };

  const handleSelectHistoryRun = async (simId: string) => {
    try {
      const run = await api.simulation(simId);
      setCurrentRun(run);
    } catch (e) {
      console.error("Failed to load historical run", e);
    }
  };

  const handleReset = () => {
    setCurrentRun(null);
    setSimError(null);
  };

  if (twinAsync.loading) {
    return <LoadingState label="Loading Digital Twin & Scenarios..." />;
  }

  if (twinAsync.error) {
    return <ErrorState message={twinAsync.error} onRetry={twinAsync.reload} />;
  }

  const selectedScenario = scenariosList.find((s) => s.scenario_id === selectedScenarioId);

  return (
    <div className="space-y-6">
      {/* Header & Controls Panel */}
      <div className="panel p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h2 className="text-xl font-bold text-white">Controlled Digital Twin Attack Simulator</h2>
            <p className="mt-1 text-xs text-[var(--muted)]">
              Simulate analytical attack propagation over the dynamic Digital Twin graph state. Synthetic research model — no real exploitation.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <select
              className="rounded-lg border border-[var(--border)] bg-[var(--bg-panel)] px-3 py-2 text-sm text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
              value={selectedScenarioId}
              onChange={(e) => {
                setSelectedScenarioId(e.target.value);
                setCurrentRun(null);
              }}
            >
              <optgroup label="Formal Synthetic Scenarios">
                {scenariosList.map((s) => (
                  <option key={s.scenario_id} value={s.scenario_id}>
                    {s.scenario_code} — {s.scenario_name}
                  </option>
                ))}
              </optgroup>
              <option value="custom">⚡ Custom Ad-Hoc Source & Target</option>
            </select>

            {selectedScenarioId === "custom" && (
              <div className="flex items-center gap-2">
                <select
                  className="rounded-lg border border-[var(--border)] bg-[var(--bg-panel)] px-2.5 py-2 text-xs text-[var(--text)]"
                  value={customSourceId}
                  onChange={(e) => setCustomSourceId(e.target.value)}
                >
                  <option value="">-- Source Asset --</option>
                  {assetsList.map((a) => (
                    <option key={a.asset_id} value={a.asset_id}>
                      {a.asset_name} ({a.layer})
                    </option>
                  ))}
                </select>
                <span className="text-xs text-[var(--muted)]">→</span>
                <select
                  className="rounded-lg border border-[var(--border)] bg-[var(--bg-panel)] px-2.5 py-2 text-xs text-[var(--text)]"
                  value={customTargetId}
                  onChange={(e) => setCustomTargetId(e.target.value)}
                >
                  <option value="">-- Target Asset --</option>
                  {assetsList.map((a) => (
                    <option key={a.asset_id} value={a.asset_id}>
                      {a.asset_name} ({a.layer})
                    </option>
                  ))}
                </select>
              </div>
            )}

            <button
              type="button"
              onClick={handleRunSimulation}
              disabled={isSimulating}
              className="rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-semibold text-white transition hover:opacity-90 disabled:opacity-50"
            >
              {isSimulating ? "Simulating..." : "🚀 Run Attack Simulation"}
            </button>

            {currentRun && (
              <button
                type="button"
                onClick={handleReset}
                className="rounded-lg border border-[var(--border)] px-3 py-2 text-xs text-[var(--muted)] hover:bg-[var(--bg-panel)] hover:text-white"
              >
                🔄 Reset State
              </button>
            )}
          </div>
        </div>

        {simError && (
          <div className="mt-4 rounded-lg border border-[var(--danger)] bg-red-950/30 p-3 text-xs text-red-300">
            {simError}
          </div>
        )}

        {/* Selected Scenario Metadata */}
        {selectedScenarioId !== "custom" && selectedScenario && (
          <div className="mt-4 flex flex-wrap items-center gap-4 rounded-lg bg-black/20 p-3 text-xs text-[var(--muted)]">
            <div>
              <span className="font-semibold text-white">Scenario:</span>{" "}
              <span className="rounded bg-[var(--accent)] px-1.5 py-0.5 text-[10px] text-white">{selectedScenario.scenario_code}</span>{" "}
              {selectedScenario.scenario_name}
            </div>
            <div>
              <span className="font-semibold text-white">Source:</span> {selectedScenario.source_name}
            </div>
            <div>
              <span className="font-semibold text-white">Target:</span> {selectedScenario.target_name}
            </div>
            <div>
              <span className="font-semibold text-white">Type:</span>{" "}
              <span className="rounded bg-purple-950 px-1.5 py-0.5 text-[10px] text-purple-200 border border-purple-800">{selectedScenario.attack_type}</span>
            </div>
            <div className="w-full text-slate-300">{selectedScenario.description}</div>
          </div>
        )}
      </div>

      {/* Simulation Result Summary Banner */}
      {currentRun && (
        <div
          className={`panel border-l-4 p-5 ${
            currentRun.result === "SUCCESS"
              ? "border-l-emerald-500 bg-emerald-950/20"
              : "border-l-rose-500 bg-rose-950/20"
          }`}
        >
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="flex items-center gap-3">
                <span
                  className={`rounded-md px-2.5 py-1 text-xs font-bold text-white ${
                    currentRun.result === "SUCCESS" ? "bg-emerald-600" : "bg-rose-600"
                  }`}
                >
                  {currentRun.result === "SUCCESS" ? "🎯 ATTACK SUCCESSFUL" : "🛑 ATTACK BLOCKED"}
                </span>
                <span className="text-sm font-semibold text-white">
                  Target Reached: {currentRun.target_reached ? "YES" : "NO"}
                </span>
                <span className="text-xs text-[var(--muted)]">Run ID: {currentRun.simulation_id.slice(0, 8)}</span>
              </div>
              <p className="mt-2 text-xs text-slate-200">
                {currentRun.block_reason || currentRun.explanation}
              </p>
            </div>

            <div className="flex flex-wrap gap-4 text-xs">
              <div className="rounded-lg bg-black/40 px-3 py-2 text-center">
                <div className="text-[var(--muted)]">Compromised</div>
                <div className="text-lg font-bold text-red-400">
                  {currentRun.compromised_asset_ids.length} Assets
                </div>
              </div>
              <div className="rounded-lg bg-black/40 px-3 py-2 text-center">
                <div className="text-[var(--muted)]">Path Length</div>
                <div className="text-lg font-bold text-cyan-400">
                  {currentRun.path_asset_ids.length} Hop(s)
                </div>
              </div>
              {currentRun.impact && (
                <div className="rounded-lg bg-black/40 px-3 py-2 text-center">
                  <div className="text-[var(--muted)]">Impact Score</div>
                  <div className="text-lg font-bold text-amber-400">
                    {currentRun.impact.impact_score} / 100
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Interactive Topology Canvas with State Visualization */}
      {twin && (
        <div className="panel p-5">
          <h3 className="mb-3 text-base font-semibold text-white">
            Digital Twin Security Topology & Simulation State
          </h3>
          <TopologyCanvas
            twin={twin}
            compromisedAssetIds={currentRun ? currentRun.compromised_asset_ids : []}
            pathAssetIds={currentRun ? currentRun.path_asset_ids : []}
            targetAssetId={
              currentRun
                ? currentRun.path_asset_ids[currentRun.path_asset_ids.length - 1]
                : selectedScenario?.target_asset_id
            }
          />
        </div>
      )}

      {/* Details Grid: Impact & Risk Comparison */}
      {currentRun && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Attack Impact & Blast Radius Analysis */}
          {currentRun.impact && (
            <div className="panel p-5">
              <h3 className="mb-4 text-base font-semibold text-white">
                Analytical Attack Impact & Blast Radius
              </h3>
              <div className="space-y-4 text-xs">
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                  <StatCard label="Compromised Assets" value={currentRun.impact.compromised_count} />
                  <StatCard label="Reachable Assets" value={currentRun.impact.reachable_count} />
                  <StatCard label="Critical Reached" value={currentRun.impact.critical_reached_count} />
                  <StatCard label="Sensitive Data Reached" value={currentRun.impact.sensitive_data_reached_count} />
                  <StatCard label="Propagation Depth" value={currentRun.impact.propagation_depth} />
                  <StatCard label="Blast Radius Score" value={`${currentRun.impact.blast_radius_score} / 100`} />
                </div>

                {currentRun.impact.explanation && (
                  <div className="rounded-lg bg-black/30 p-3 text-slate-300">
                    {currentRun.impact.explanation}
                  </div>
                )}

                {currentRun.impact.factors.length > 0 && (
                  <div>
                    <h4 className="mb-2 font-semibold text-slate-200">Impact Factor Breakdown</h4>
                    <div className="space-y-2">
                      {currentRun.impact.factors.map((f, i) => (
                        <div key={i} className="flex items-center justify-between rounded bg-[var(--bg-panel)] p-2">
                          <div>
                            <div className="font-semibold text-slate-200">{f.name.replaceAll("_", " ")}</div>
                            <div className="text-[10px] text-[var(--muted)]">{f.detail}</div>
                          </div>
                          <div className="text-right">
                            <span className="font-mono text-cyan-400">+{f.contribution ?? (f.weighted_contribution * 100).toFixed(1)}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Baseline vs Simulation Risk Comparison */}
          {currentRun.risk_comparison && (
            <div className="panel p-5">
              <h3 className="mb-4 text-base font-semibold text-white">
                Baseline Risk vs. Simulation-Impact Risk
              </h3>
              <div className="space-y-4 text-xs">
                <div className="grid grid-cols-3 gap-3 text-center">
                  <div className="rounded-lg bg-black/40 p-3">
                    <div className="text-[var(--muted)]">Baseline Risk</div>
                    <div className="text-lg font-bold text-slate-100">
                      {currentRun.risk_comparison.baseline_risk}
                    </div>
                    <BandBadge band={currentRun.risk_comparison.baseline_band} />
                  </div>
                  <div className="rounded-lg bg-black/40 p-3">
                    <div className="text-[var(--muted)]">Simulation Risk</div>
                    <div className="text-lg font-bold text-amber-400">
                      {currentRun.risk_comparison.simulation_risk}
                    </div>
                    <BandBadge band={currentRun.risk_comparison.simulation_band} />
                  </div>
                  <div className="rounded-lg bg-black/40 p-3">
                    <div className="text-[var(--muted)]">Risk Delta (Δ)</div>
                    <div
                      className={`text-lg font-bold ${
                        currentRun.risk_comparison.risk_change >= 0 ? "text-rose-400" : "text-emerald-400"
                      }`}
                    >
                      {currentRun.risk_comparison.risk_change >= 0 ? "+" : ""}
                      {currentRun.risk_comparison.risk_change}
                    </div>
                    <span className="text-[10px] text-[var(--muted)]">Impact Overlay</span>
                  </div>
                </div>

                <div className="rounded-lg bg-black/30 p-3 text-slate-300">
                  {currentRun.risk_comparison.explanation}
                </div>

                {currentRun.risk_comparison.notes.length > 0 && (
                  <ul className="list-disc space-y-1 pl-4 text-[var(--muted)]">
                    {currentRun.risk_comparison.notes.map((note, i) => (
                      <li key={i}>{note}</li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Step-by-Step Simulation Event Timeline Table */}
      {currentRun && currentRun.events.length > 0 && (
        <div className="panel p-5">
          <h3 className="mb-4 text-base font-semibold text-white">
            Simulation Event Timeline ({currentRun.events.length} Steps)
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-black/40 text-[var(--muted)]">
                <tr>
                  <th className="px-3 py-2 font-medium">Step #</th>
                  <th className="px-3 py-2 font-medium">Action</th>
                  <th className="px-3 py-2 font-medium">Source → Target</th>
                  <th className="px-3 py-2 font-medium">Finding / Vuln</th>
                  <th className="px-3 py-2 font-medium">State Transition</th>
                  <th className="px-3 py-2 font-medium">Result / Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-200">
                {currentRun.events.map((ev) => (
                  <tr key={ev.event_id} className="hover:bg-slate-900/40">
                    <td className="px-3 py-2 font-mono text-[var(--muted)]">Step {ev.step_number}</td>
                    <td className="px-3 py-2">
                      <span
                        className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                          ev.success ? "bg-emerald-950 text-emerald-300 border border-emerald-800" : "bg-rose-950 text-rose-300 border border-rose-800"
                        }`}
                      >
                        {ev.action}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-medium text-slate-100">
                      {ev.source_name || "Start"}{" "}
                      {ev.target_name ? `→ ${ev.target_name}` : ""}
                    </td>
                    <td className="px-3 py-2 font-mono text-amber-300">
                      {ev.vulnerability_identifier || "—"}
                    </td>
                    <td className="px-3 py-2 font-mono text-[var(--muted)]">
                      {ev.previous_state} → {ev.new_state}
                    </td>
                    <td className="max-w-md px-3 py-2 text-slate-300">{ev.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Simulation History Table */}
      {historyList.length > 0 && (
        <div className="panel p-5">
          <h3 className="mb-4 text-base font-semibold text-white">
            Simulation History & Provenance Log
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-black/40 text-[var(--muted)]">
                <tr>
                  <th className="px-3 py-2 font-medium">Time</th>
                  <th className="px-3 py-2 font-medium">Scenario</th>
                  <th className="px-3 py-2 font-medium">Result</th>
                  <th className="px-3 py-2 font-medium">Target Reached</th>
                  <th className="px-3 py-2 font-medium">Compromised</th>
                  <th className="px-3 py-2 font-medium">Impact Score</th>
                  <th className="px-3 py-2 font-medium">Sim Risk</th>
                  <th className="px-3 py-2 font-medium">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-200">
                {historyList.map((h) => (
                  <tr key={h.simulation_id} className="hover:bg-slate-900/40">
                    <td className="px-3 py-2 font-mono text-[var(--muted)]">
                      {new Date(h.created_at).toLocaleTimeString()}
                    </td>
                    <td className="px-3 py-2 font-medium text-white">
                      {h.scenario_code ? `${h.scenario_code} — ` : ""}{h.scenario_name || "Ad-Hoc"}
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                          h.result === "SUCCESS"
                            ? "bg-emerald-950 text-emerald-300 border border-emerald-800"
                            : "bg-rose-950 text-rose-300 border border-rose-800"
                        }`}
                      >
                        {h.result}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono">
                      {h.target_reached ? "YES 🎯" : "NO 🛑"}
                    </td>
                    <td className="px-3 py-2 font-mono text-red-400">
                      {h.compromised_count} Assets
                    </td>
                    <td className="px-3 py-2 font-mono text-amber-300">
                      {h.impact_score !== null ? `${h.impact_score} / 100` : "—"}
                    </td>
                    <td className="px-3 py-2 font-mono text-cyan-300">
                      {h.simulation_risk !== null ? h.simulation_risk : "—"}
                    </td>
                    <td className="px-3 py-2">
                      <button
                        type="button"
                        onClick={() => handleSelectHistoryRun(h.simulation_id)}
                        className="rounded border border-[var(--border)] px-2 py-0.5 text-[10px] text-[var(--muted)] hover:bg-[var(--bg-panel)] hover:text-white"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
