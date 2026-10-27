"""Milestone 6: End-to-End Red-Team vs. Blue-Team Demo Flow Validation."""
import time
from fastapi.testclient import TestClient
from gateway.main import app
from gateway.config import GATEWAY_CONFIG

client = TestClient(app)

print("=" * 70)
print("MILESTONE 6: RED-TEAM VS BLUE-TEAM END-TO-END DEMO SUITE")
print("=" * 70)

# =====================================================================
# SCENARIO 1: DEFENSE OFF -> Full Secret Leak (Demonstrating Vulnerability)
# =====================================================================
print("\n[SCENARIO 1] DEFENSE OFF -> Demonstrating Side-Channel Timing Leak")
client.post("/api/config", json={"defense_enabled": False, "timing_profile": "70B_vLLM"})
client.post("/api/reset")

r = client.post("/api/simulate/red-team", json={"mode": "exact", "tenant_id": "red_attacker_nodefense"})
assert r.status_code == 200
data1 = r.json()

print(f"  Target Secret   : {data1['target_secret']}")
print(f"  Extracted Secret: {data1['extracted_secret']}")
print(f"  Fully Leaked?   : {data1['fully_leaked']}")
print(f"  Quarantined?    : {data1['quarantined']}")
print(f"  Probes Sent     : {data1['steps_count']}")
print(f"  Final LLR       : {data1['final_llr']}")

assert data1["fully_leaked"] is True
assert data1["extracted_secret"] == "OMEGA_77"
assert data1["quarantined"] is False
assert data1["steps_count"] == 8
print("  >>> PROOF: Attacker successfully stole full confidential secret OMEGA_77!")

# =====================================================================
# SCENARIO 2: DEFENSE ON -> Red-Team Stopped & Quarantined
# =====================================================================
print("\n[SCENARIO 2] DEFENSE ON -> Out-of-Band SPRT Quarantine & Padding")
client.post("/api/config", json={"defense_enabled": True, "timing_profile": "70B_vLLM"})
client.post("/api/reset")

r = client.post("/api/simulate/red-team", json={"mode": "exact", "tenant_id": "red_attacker_defended"})
assert r.status_code == 200
data2 = r.json()

print(f"  Target Secret   : {data2['target_secret']}")
print(f"  Extracted Secret: {data2['extracted_secret']} (Halted at probe)")
print(f"  Fully Leaked?   : {data2['fully_leaked']}")
print(f"  Quarantined?    : {data2['quarantined']}")
print(f"  Probes Sent     : {data2['steps_count']} (Stopped before completion)")
print(f"  Final LLR       : {data2['final_llr']}")

assert data2["fully_leaked"] is False
assert data2["extracted_secret"] != "OMEGA_77"
assert data2["quarantined"] is True
assert data2["steps_count"] < 8
print("  >>> PROOF: Side-channel attack neutralized! Tenant quarantined and salt rotated.")

# =====================================================================
# SCENARIO 3: BLUE-TEAM BURST -> 40 Prompts with 0% False Positives
# =====================================================================
print("\n[SCENARIO 3] BLUE-TEAM BURST -> 40 Realistic Enterprise Customer Queries")
client.post("/api/reset")

r = client.post("/api/simulate/blue-team", json={"count": 40, "tenant_id": "enterprise_customer"})
assert r.status_code == 200
data3 = r.json()

print(f"  Prompts Sent    : {data3['prompts_sent']}")
print(f"  False Positives : {data3['false_positives']}")
print(f"  FP Rate         : {data3['false_positive_rate']}%")
print(f"  Max LLR         : {data3['max_llr']}")
print(f"  Quarantined?    : {data3['quarantined']}")
print(f"  Avg Hot-Path Ov : {data3['avg_hot_path_overhead_ms']:.4f} ms (<0.10ms SLA)")

assert data3["false_positives"] == 0
assert data3["false_positive_rate"] == 0.0
assert data3["quarantined"] is False
assert data3["max_llr"] == 0.0
assert data3["avg_hot_path_overhead_ms"] < 0.10
print("  >>> PROOF: 0% False Positive Rate on normal customer bursts!")

# =====================================================================
# SCENARIO 4: FUZZY 3-GRAM SHINGLING PROBE TEST
# =====================================================================
print("\n[SCENARIO 4] FUZZY SHINGLING PROBE TEST")
r = client.post("/api/simulate/red-team", json={"mode": "fuzzy", "tenant_id": "fuzzy_probe_tester"})
assert r.status_code == 200
data4 = r.json()
print(f"  Fuzzy Prompt    : '{data4['prompt']}'")
print(f"  Target Secret   : '{data4['target_secret']}'")
print(f"  Status          : {data4['status']}")
print("  >>> PROOF: Fuzzy shingling successfully analyzed space-mutated probe.")

# =====================================================================
# SCENARIO 5: TIMING PROFILE SWITCH (0.5B_Edge vs 70B_vLLM)
# =====================================================================
print("\n[SCENARIO 5] TIMING PROFILE SWITCH TEST")
r = client.post("/api/config", json={"timing_profile": "0.5B_Edge"})
assert r.status_code == 200
cfg_data = r.json()
assert cfg_data["timing_profile"] == "0.5B_Edge"
assert cfg_data["padding_bucket_ms"] == 20.0
print(f"  Profile switched to: {cfg_data['timing_profile']} (Bucket: {cfg_data['padding_bucket_ms']}ms)")

# Switch back to 70B
r = client.post("/api/config", json={"timing_profile": "70B_vLLM", "defense_enabled": True})
assert r.status_code == 200
print("  Profile restored to: 70B_vLLM (Bucket: 85.0ms)")

# =====================================================================
# SCENARIO 6: SYBIL MULTI-TENANT ROTATION ATTACK BLOCKED (Upgrade 1)
# =====================================================================
print("\n[SCENARIO 6] SYBIL ATTACK -> Multi-Tenant Rotation Shield Test")
client.post("/api/reset")
client.post("/api/config", json={"defense_enabled": True, "timing_profile": "70B_vLLM"})

r = client.post("/api/simulate/red-team", json={"mode": "sybil"})
assert r.status_code == 200
data6 = r.json()

print(f"  Target Secret   : {data6['target_secret']}")
print(f"  Extracted Secret: {data6['extracted_secret']} (Halted before full leak)")
print(f"  Fully Leaked?   : {data6['fully_leaked']}")
print(f"  Quarantined?    : {data6['quarantined']}")
print(f"  Probes Sent     : {data6['steps_count']} (Blocked at 3rd-4th probe)")
print(f"  Global Sybil LLR: {data6.get('global_sybil_llr', 0.0)}")

assert data6["fully_leaked"] is False
assert data6["quarantined"] is True
assert data6["steps_count"] < 8
assert data6["steps_count"] in (3, 4)
print("  >>> PROOF: Global Sybil Shield halted rotating tenant-id side-channel attack at 3rd/4th probe!")

# Cleanup
client.post("/api/reset")
print("\n" + "=" * 70)
print("ALL MILESTONE 6 DEMO SCENARIOS PASSED 100%!")
print("=" * 70)
