export function riskColor(band?: string | null): string {
  switch (band) {
    case "CRITICAL":
      return "#c45c5c";
    case "HIGH":
      return "#c48a3a";
    case "MEDIUM":
      return "#c4a35a";
    case "LOW":
      return "#3d7ea6";
    case "VERY_LOW":
      return "#1f8a70";
    default:
      return "#8aa0ab";
  }
}

export function criticalityLabel(value: number): string {
  return ["", "Very Low", "Low", "Medium", "High", "Critical"][value] ?? String(value);
}

export function layerColor(layer: string): string {
  switch (layer) {
    case "IOT":
      return "#2f6f8f";
    case "EDGE":
      return "#3d7a5f";
    case "NETWORK":
      return "#6b5b95";
    case "CLOUD":
      return "#1f8a70";
    case "APPLICATION":
      return "#b07d4f";
    case "DATA":
      return "#c45c5c";
    case "USER":
      return "#3d7ea6";
    default:
      return "#4a5c66";
  }
}
