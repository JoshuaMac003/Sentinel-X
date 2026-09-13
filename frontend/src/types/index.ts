export type Criticality = 1 | 2 | 3 | 4 | 5;

export interface AssetService {
  service_id: string;
  service_name: string;
  protocol?: string | null;
  port?: number | null;
}

export interface Asset {
  asset_id: string;
  asset_name: string;
  asset_type: string;
  layer: string;
  description?: string | null;
  ip_address?: string | null;
  operating_system?: string | null;
  criticality: Criticality;
  trust_level: string;
  status: string;
  services: AssetService[];
}

export interface Vulnerability {
  vulnerability_id: string;
  asset_id: string;
  identifier: string;
  name: string;
  description?: string | null;
  severity: string;
  cvss_score: number;
  exploitability: string;
  status: string;
  remediation?: string | null;
  is_synthetic: boolean;
}

export interface Relationship {
  relationship_id: string;
  source_asset_id: string;
  target_asset_id: string;
  relationship_type: string;
  protocol?: string | null;
  port?: number | null;
  trust_level: string;
  description?: string | null;
}

export interface TwinAsset {
  asset_id: string;
  asset_name: string;
  asset_type: string;
  layer: string;
  criticality: Criticality;
  trust_level: string;
  status: string;
  ip_address?: string | null;
  security_state: string;
  vulnerability_count: number;
  open_vulnerability_count: number;
  services: { service_name: string; protocol?: string | null; port?: number | null }[];
  vulnerabilities: {
    vulnerability_id: string;
    identifier: string;
    name: string;
    severity: string;
    cvss_score: number;
    exploitability: string;
    status: string;
    is_synthetic: boolean;
  }[];
}

export interface TwinEdge {
  relationship_id: string;
  source_asset_id: string;
  target_asset_id: string;
  source_name: string;
  target_name: string;
  relationship_type: string;
  protocol?: string | null;
  port?: number | null;
  trust_level: string;
}

export interface DigitalTwin {
  generated_at: string;
  environment: string;
  asset_count: number;
  relationship_count: number;
  vulnerability_count: number;
  critical_asset_count: number;
  assets: TwinAsset[];
  relationships: TwinEdge[];
  topology: {
    nodes: TwinAsset[];
    edges: TwinEdge[];
    layers: { layer: string; asset_ids: string[] }[];
  };
  notes: string[];
}

export interface AttackPathHop {
  asset_id: string;
  asset_name: string;
  asset_type: string;
}

export interface AttackPath {
  path_id: string;
  source_asset_id: string;
  source_name: string;
  target_asset_id: string;
  target_name: string;
  hops: AttackPathHop[];
  asset_ids: string[];
  stage_count: number;
  length: number;
  vulnerabilities_on_path: string[];
  scenario_label?: string | null;
  explanation: string;
  risk_score?: number | null;
  risk_band?: string | null;
}

export interface RiskFactor {
  name: string;
  value: number;
  weight: number;
  weighted_contribution: number;
  contribution?: number;
  detail: string;
}

export interface AssetRisk {
  asset_id: string;
  asset_name: string;
  risk_score: number;
  risk_band: string;
  factors: RiskFactor[];
  explanation: string;
}

export interface PathRisk {
  path_id: string;
  source_name: string;
  target_name: string;
  path_display: string;
  stage_count: number;
  risk_score: number;
  risk_band: string;
  factors: RiskFactor[];
  explanation: string;
  scenario_label?: string | null;
}

export interface RiskOverview {
  overall_risk_score: number;
  overall_risk_band: string;
  model_version: string;
  asset_count: number;
  assessed_assets: number;
  path_count: number;
  high_or_critical_assets: number;
  high_or_critical_paths: number;
  factors_summary: RiskFactor[];
  explanation: string;
  high_risk_assets: AssetRisk[];
  high_risk_paths: PathRisk[];
  distribution: Record<string, number>;
  notes: string[];
}

export interface Scenario {
  scenario_id: string;
  scenario_code: string;
  scenario_name: string;
  description?: string | null;
  source_asset_id: string;
  source_name: string;
  target_asset_id: string;
  target_name: string;
  attack_type: string;
  enabled: boolean;
  preferred_waypoints: string[];
  notes?: string | null;
}

export interface SimulationEvent {
  event_id: string;
  simulation_id: string;
  step_number: number;
  source_asset_id?: string | null;
  source_name?: string | null;
  target_asset_id?: string | null;
  target_name?: string | null;
  action: string;
  reason: string;
  vulnerability_identifier?: string | null;
  previous_state: string;
  new_state: string;
  success: boolean;
  risk_impact: number;
  timestamp: string;
}

export interface BlastRadius {
  origin_asset_id: string;
  origin_name: string;
  reachable_asset_count: number;
  vulnerable_reachable_count: number;
  critical_assets_reachable: number;
  sensitive_data_assets_reached: number;
  maximum_propagation_depth: number;
  impact_score: number;
  reachable_asset_ids: string[];
  explanation: string;
}

export interface SimulationImpact {
  impact_id: string;
  simulation_id: string;
  propagation_depth: number;
  compromised_count: number;
  reachable_count: number;
  vulnerable_reachable_count: number;
  critical_reached_count: number;
  sensitive_data_reached_count: number;
  target_reached: boolean;
  maximum_propagation_depth: number;
  impact_score: number;
  blast_radius_score: number;
  blast_radius?: BlastRadius | null;
  factors: RiskFactor[];
  explanation?: string | null;
  propagation_path: string[];
  compromised_asset_ids: string[];
  compromised_asset_names: string[];
}

export interface RiskComparison {
  simulation_id: string;
  baseline_risk: number;
  baseline_band: string;
  simulation_risk: number;
  simulation_band: string;
  risk_change: number;
  factors: RiskFactor[];
  explanation: string;
  model_version: string;
  notes: string[];
}

export interface SimulationSummary {
  simulation_id: string;
  scenario_id?: string | null;
  scenario_code?: string | null;
  scenario_name?: string | null;
  result: "SUCCESS" | "BLOCKED" | "NO_PATH" | "FAILED";
  target_reached: boolean;
  step_count: number;
  compromised_count: number;
  impact_score?: number | null;
  baseline_risk?: number | null;
  simulation_risk?: number | null;
  risk_change?: number | null;
  created_at: string;
  block_reason?: string | null;
}

export interface SimulationRun {
  simulation_id: string;
  scenario?: Scenario | null;
  result: "SUCCESS" | "BLOCKED" | "NO_PATH" | "FAILED";
  target_reached: boolean;
  block_reason?: string | null;
  path_asset_ids: string[];
  path_display: string;
  compromised_asset_ids: string[];
  isolated_asset_ids: string[];
  events: SimulationEvent[];
  impact?: SimulationImpact | null;
  risk_comparison?: RiskComparison | null;
  explanation?: string | null;
  model_version: string;
  created_at: string;
}
