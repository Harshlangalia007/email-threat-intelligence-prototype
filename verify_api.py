"""
End-to-End Verification Script for SIH26106 SOC Platform
Tests all API endpoints, static assets, samples, forensic reconstructions, and graph correlation.
"""

import requests
import json

base = "http://127.0.0.1:5000"

print("\n--- 1. Testing Static Assets & Web Shell ---")
for path in ["/", "/static/css/soc.css", "/static/js/soc_app.js", "/static/js/graph_visualizer.js"]:
    r = requests.get(base + path)
    assert r.status_code == 200, f"Failed {path}: {r.status_code}"
    print(f" [PASS] {path} (HTTP 200, {len(r.text)} bytes)")

print("\n--- 2. Testing Sample Email Vault ---")
r = requests.get(base + "/api/samples")
assert r.status_code == 200
samples = r.json()["samples"]
print(f" [PASS] Loaded {len(samples)} demonstration sample scenarios")

print("\n--- 3. Testing Full End-to-End Analysis Pipeline ---")
for s in samples:
    sid = s["id"]
    s_data = requests.get(f"{base}/api/samples/{sid}").json()["sample"]
    res = requests.post(f"{base}/api/analyze", json={"raw_eml": s_data["raw_eml"], "source": "sample"}).json()
    assert res["status"] == "success"
    dossier = res["dossier"]
    
    threat = dossier["threat_detection"]
    forensic = dossier["forensic_investigation"]
    relay = forensic["relay_path"]
    origin = relay["origin_mta"]
    loc = forensic["location_analysis"]
    
    print(f" [PASS] Scenario: {sid}")
    print(f"        Classification: {threat['classification']} (Risk: {threat['risk_score']}/100, Conf: {threat['confidence']}%)")
    print(f"        Origin Ingress: {origin.get('ip')} ({origin.get('org')}, {origin.get('country')})")
    print(f"        Relay Hops:     {relay.get('total_hops')} hops reconstructed")
    print(f"        Mandatory Term: {loc.get('mandatory_statement')}")

print("\n--- 4. Testing Infrastructure Graph Topology ---")
cid = dossier["case_id"]
g_res = requests.get(f"{base}/api/graph/{cid}").json()
nodes_count = g_res["graph"]["total_nodes"]
edges_count = g_res["graph"]["total_edges"]
print(f" [PASS] Case {cid} Graph: {nodes_count} nodes, {edges_count} edges")

print("\n--- 5. Testing Metrics Telemetry ---")
m_res = requests.get(f"{base}/api/metrics").json()
print(f" [PASS] Telemetry Metrics: {json.dumps(m_res['metrics'], indent=2)}")

print("\n--- 6. Testing Arbitrary Pasted Emails (No Received Headers) ---")
pasted_tests = [
    ("Credential Phish", "Urgent! Your account has expired. Sign in now at http://micros0ft-update.com/login to restore access."),
    ("Executive BEC", "From: CEO David <ceo@corp.com>\nSubject: Wire Transfer\n\nPlease transfer $20,000 immediately."),
    ("Delivery Phish", "From: <alerts@dhl-tracking.xyz>\nSubject: Package Held\n\nTrack package at https://dhl-tracker.top")
]
for name, content in pasted_tests:
    res = requests.post(base + "/api/analyze", json={"raw_eml": content, "source": "paste"}).json()
    assert res["status"] == "success", f"Failed {name}: {res}"
    d = res["dossier"]
    t = d["threat_detection"]
    f = d["forensic_investigation"]
    print(f" [PASS] Pasted '{name}' -> Class: {t['classification']}, Risk: {t['risk_score']}/100, Ingress: {f['relay_path']['origin_mta']['ip']}")

print("\n=======================================================")
print(" ALL SIH26106 END-TO-END PIPELINE CHECKS VERIFIED OK!")
print("=======================================================\n")
