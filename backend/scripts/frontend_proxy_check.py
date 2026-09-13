import json
import urllib.request

print("frontend", urllib.request.urlopen("http://127.0.0.1:5173/").status)
print("proxy_health", json.load(urllib.request.urlopen("http://127.0.0.1:5173/api/health")))
risk = json.load(urllib.request.urlopen("http://127.0.0.1:5173/api/risk"))
print("proxy_risk", risk["overall_risk_score"], risk["overall_risk_band"])
twin = json.load(urllib.request.urlopen("http://127.0.0.1:5173/api/digital-twin"))
print("proxy_twin", twin["asset_count"], twin["relationship_count"])
print("FRONTEND_LIVE_OK")
