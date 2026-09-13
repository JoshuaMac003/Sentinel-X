import { memo, useMemo } from "react";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import type { DigitalTwin } from "../types";
import { layerColor } from "../utils/style";

const LAYER_Y: Record<string, number> = {
  IOT: 0,
  EDGE: 140,
  NETWORK: 280,
  CLOUD: 420,
  APPLICATION: 560,
  DATA: 700,
  USER: 840,
};

type TwinNodeData = {
  name: string;
  layer: string;
  assetType: string;
  criticality: number;
  securityState: string;
  color: string;
  isCompromised?: boolean;
  isTarget?: boolean;
  isBlocked?: boolean;
  isOnPath?: boolean;
};

function TwinNode({ data }: NodeProps & { data: TwinNodeData }) {
  let badgeText = data.securityState;
  let badgeColor = "bg-black/30 text-white/90";
  let borderStyle = "border-white/25";

  if (data.isCompromised) {
    badgeText = "☣️ COMPROMISED";
    badgeColor = "bg-red-950 text-red-200 border border-red-500/50";
    borderStyle = "border-red-500 shadow-[0_0_12px_rgba(239,68,68,0.5)] animate-pulse";
  } else if (data.isTarget) {
    badgeText = "🎯 TARGET";
    badgeColor = "bg-amber-950 text-amber-200 border border-amber-500/50";
    borderStyle = "border-amber-400 shadow-[0_0_10px_rgba(245,158,11,0.4)]";
  } else if (data.isBlocked) {
    badgeText = "🛑 BLOCKED";
    badgeColor = "bg-slate-900 text-slate-300 border border-slate-600";
    borderStyle = "border-slate-500 opacity-70";
  } else if (data.isOnPath) {
    badgeText = "⚡ PATH";
    badgeColor = "bg-cyan-950 text-cyan-200 border border-cyan-500/50";
    borderStyle = "border-cyan-400";
  }

  return (
    <div
      className={`rounded-[10px] border px-2.5 py-2 text-left text-white shadow-sm transition-all duration-300 ${borderStyle}`}
      style={{ background: data.color, width: 185 }}
    >
      <Handle type="target" position={Position.Top} className="!bg-white/70" />
      <div className="flex items-center justify-between">
        <div className="text-[10px] uppercase tracking-wide opacity-80">{data.layer}</div>
        <span className={`rounded px-1.5 py-0.5 text-[9px] font-bold ${badgeColor}`}>
          {badgeText}
        </span>
      </div>
      <div className="mt-1 text-sm font-semibold leading-tight">{data.name}</div>
      <div className="mt-1 text-[10px] opacity-80">
        {data.assetType} · C{data.criticality}
      </div>
      <Handle type="source" position={Position.Bottom} className="!bg-white/70" />
    </div>
  );
}

const nodeTypes = { twin: memo(TwinNode) };

interface TopologyCanvasProps {
  twin: DigitalTwin;
  compromisedAssetIds?: string[];
  pathAssetIds?: string[];
  targetAssetId?: string;
  blockedAssetId?: string;
}

export function TopologyCanvas({
  twin,
  compromisedAssetIds = [],
  pathAssetIds = [],
  targetAssetId,
  blockedAssetId,
}: TopologyCanvasProps) {
  const compSet = useMemo(() => new Set(compromisedAssetIds), [compromisedAssetIds]);
  const pathSet = useMemo(() => new Set(pathAssetIds), [pathAssetIds]);

  const { nodes, edges } = useMemo(() => {
    const layerBuckets = new Map<string, typeof twin.assets>();
    for (const asset of twin.topology.nodes) {
      const list = layerBuckets.get(asset.layer) ?? [];
      list.push(asset);
      layerBuckets.set(asset.layer, list);
    }

    const builtNodes: Node[] = [];
    for (const [layer, assets] of layerBuckets.entries()) {
      assets.forEach((asset, index) => {
        const isComp = compSet.has(asset.asset_id);
        const isTgt = targetAssetId === asset.asset_id;
        const isBlk = blockedAssetId === asset.asset_id;
        const isOnP = pathSet.has(asset.asset_id);

        builtNodes.push({
          id: asset.asset_id,
          type: "twin",
          position: { x: 40 + index * 210, y: LAYER_Y[layer] ?? 0 },
          data: {
            name: asset.asset_name,
            layer: asset.layer,
            assetType: asset.asset_type,
            criticality: asset.criticality,
            securityState: isComp ? "COMPROMISED" : asset.security_state,
            color: isComp ? "#7f1d1d" : layerColor(asset.layer),
            isCompromised: isComp,
            isTarget: isTgt,
            isBlocked: isBlk,
            isOnPath: isOnP,
          },
        });
      });
    }

    const builtEdges: Edge[] = twin.topology.edges.map((edge) => {
      const isPathEdge =
        pathSet.has(edge.source_asset_id) && pathSet.has(edge.target_asset_id);
      return {
        id: edge.relationship_id,
        source: edge.source_asset_id,
        target: edge.target_asset_id,
        label: edge.relationship_type.replaceAll("_", " "),
        animated: isPathEdge || edge.trust_level === "LOW" || edge.trust_level === "UNTRUSTED",
        style: {
          stroke: isPathEdge ? "#ef4444" : "#8aa0ab",
          strokeWidth: isPathEdge ? 3.0 : 1.5,
        },
        labelStyle: { fill: isPathEdge ? "#f87171" : "#c9d6dc", fontSize: 10, fontWeight: isPathEdge ? "bold" : "normal" },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: isPathEdge ? "#ef4444" : "#8aa0ab",
        },
      };
    });

    return { nodes: builtNodes, edges: builtEdges };
  }, [twin, compSet, pathSet, targetAssetId, blockedAssetId]);

  return (
    <div className="panel h-[640px] overflow-hidden">
      <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView minZoom={0.2} maxZoom={1.5}>
        <Background gap={18} color="#24333a" />
        <MiniMap
          nodeColor={(n) => String((n.data as TwinNodeData | undefined)?.color ?? "#4a5c66")}
          maskColor="rgba(11,18,21,0.7)"
        />
        <Controls />
      </ReactFlow>
    </div>
  );
}
