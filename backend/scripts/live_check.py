"""Hit the live backend (127.0.0.1:8000) for demonstration readiness."""

from __future__ import annotations

import json
import urllib.request


def get(path: str):
    with urllib.request.urlopen(f"http://127.0.0.1:8000{path}", timeout=60) as resp:
        return json.loads(resp.read().decode())


def post(path: str):
    req = urllib.request.Request(
        f"http://127.0.0.1:8000{path}",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())


def main() -> None:
    seed = post("/api/admin/seed")
    health = get("/api/health")
    twin = get("/api/digital-twin")
    paths = get("/api/attack-paths")
    risk = get("/api/risk")
    print(
        json.dumps(
            {
                "seed": seed,
                "health": health,
                "twin_assets": twin["asset_count"],
                "twin_rels": twin["relationship_count"],
                "paths": paths["path_count"],
                "risk": risk["overall_risk_score"],
                "band": risk["overall_risk_band"],
                "scenarios": sorted(
                    {
                        p["scenario_label"]
                        for p in paths["paths"]
                        if p.get("scenario_label")
                    }
                ),
            },
            indent=2,
        )
    )
    print("LIVE_OK")


if __name__ == "__main__":
    main()
