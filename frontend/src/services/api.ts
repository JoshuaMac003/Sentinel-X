
import type {
  Asset,
  Relationship,
  Vulnerability,
  DigitalTwin,
  AttackPath,
  RiskOverview,
  AssetRisk,
  PathRisk,
  Scenario,
  SimulationRun,
  SimulationEvent,
  SimulationImpact,
  RiskComparison,
  SimulationSummary,
  SdnMonitorResponse,
} from "../types";

const API_BASE = import.meta.env.VITE_API_BASE ?? "/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      Accept: "application/json",
      ...(init?.headers ?? {}),
    },
    ...init,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed (${response.status})`);
  }

  return response.json() as Promise<T>;
}

export const api = {
  health: () =>
    request<{ status: string; app: string }>("/health"),

  seed: () =>
    request<{
      message: string;
      assets: number;
      relationships: number;
      vulnerabilities: number;
    }>("/admin/seed", {
      method: "POST",
    }),

  assets: () => request<Asset[]>("/assets"),

  relationships: () => request<Relationship[]>("/relationships"),

  vulnerabilities: () =>
    request<Vulnerability[]>("/vulnerabilities"),

  digitalTwin: () => request<DigitalTwin>("/digital-twin"),

  attackPaths: () =>
    request<{
      path_count: number;
      paths: AttackPath[];
      notes: string[];
    }>("/attack-paths"),

  riskOverview: () => request<RiskOverview>("/risk/overview"),

  riskAssets: () => request<AssetRisk[]>("/risk/assets"),

  riskPaths: () => request<PathRisk[]>("/risk/paths"),

  scenarios: () => request<Scenario[]>("/scenarios"),

  scenario: (id: string) =>
    request<Scenario>(`/scenarios/${id}`),

  runSimulation: (payload: {
    scenario_id?: string;
    source_asset_id?: string;
    target_asset_id?: string;
  }) =>
    request<SimulationRun>("/simulations", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    }),

  simulations: () =>
    request<SimulationSummary[]>("/simulations"),

  simulation: (id: string) =>
    request<SimulationRun>(`/simulations/${id}`),

  simulationEvents: (id: string) =>
    request<SimulationEvent[]>(`/simulations/${id}/events`),

  simulationImpact: (id: string) =>
    request<SimulationImpact>(`/simulations/${id}/impact`),

  riskComparison: (simulationId?: string) =>
    request<RiskComparison>(
      `/risk/comparison${
        simulationId ? `?simulation_id=${simulationId}` : ""
      }`,
    ),

  // SDN monitoring
  sdnMonitor: () =>
    request<SdnMonitorResponse>("/sdn/monitor"),
};
