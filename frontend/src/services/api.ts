const API_BASE = import.meta.env.VITE_API_BASE ?? "/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { Accept: "application/json", ...(init?.headers ?? {}) },
    ...init,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string; app: string }>("/health"),
  seed: () =>
    request<{ message: string; assets: number; relationships: number; vulnerabilities: number }>(
      "/admin/seed",
      { method: "POST" },
    ),
  assets: () => request<import("../types").Asset[]>("/assets"),
  relationships: () => request<import("../types").Relationship[]>("/relationships"),
  vulnerabilities: () => request<import("../types").Vulnerability[]>("/vulnerabilities"),
  digitalTwin: () => request<import("../types").DigitalTwin>("/digital-twin"),
  attackPaths: () =>
    request<{ path_count: number; paths: import("../types").AttackPath[]; notes: string[] }>(
      "/attack-paths",
    ),
  riskOverview: () => request<import("../types").RiskOverview>("/risk/overview"),
  riskAssets: () => request<import("../types").AssetRisk[]>("/risk/assets"),
  riskPaths: () => request<import("../types").PathRisk[]>("/risk/paths"),
  scenarios: () => request<import("../types").Scenario[]>("/scenarios"),
  scenario: (id: string) => request<import("../types").Scenario>(`/scenarios/${id}`),
  runSimulation: (payload: { scenario_id?: string; source_asset_id?: string; target_asset_id?: string }) =>
    request<import("../types").SimulationRun>("/simulations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  simulations: () => request<import("../types").SimulationSummary[]>("/simulations"),
  simulation: (id: string) => request<import("../types").SimulationRun>(`/simulations/${id}`),
  simulationEvents: (id: string) =>
    request<import("../types").SimulationEvent[]>(`/simulations/${id}/events`),
  simulationImpact: (id: string) =>
    request<import("../types").SimulationImpact>(`/simulations/${id}/impact`),
  riskComparison: (simulationId?: string) =>
    request<import("../types").RiskComparison>(
      `/risk/comparison${simulationId ? `?simulation_id=${simulationId}` : ""}`,
    ),
};
