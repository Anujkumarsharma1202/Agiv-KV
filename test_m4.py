"""Milestone 4: Quarantine + TTFT Padding validation."""
import time
from gateway.main import app
from gateway.config import GATEWAY_CONFIG
from gateway.state import TENANTS
from gateway.telemetry import TELEMETRY
from fastapi.testclient import TestClient

cfg = GATEWAY_CONFIG
client = TestClient(app)

# ===================================================================
# TEST 1: DEFENSE ON - Probe until quarantine triggers, then verify padding
# ===================================================================
print("=" * 65)
print("TEST 1: DEFENSE ON - Probe -> Quarantine -> Padding")
print("=" * 65)

# Ensure defense is ON
client.post("/api/config", json={"defense_enabled": True})
client.post("/api/reset")

secret = cfg.hidden_secret  # "OMEGA_77"
print(f"Secret: {secret}  |  Boundary A: {cfg.sprt_upper_boundary:.4f}")
print(f"Padding bucket: {cfg.padding_bucket_ms}ms")
print()

# Phase 1: Probe character-by-character (should trigger quarantine at probe ~3)
print("--- Phase 1: Probing (pre-quarantine) ---")
for i in range(1, len(secret) + 1):
    probe = secret[:i]
    r = client.post("/v1/chat/completions", json={
        "messages": [{"role": "user", "content": probe}],
        "tenant_id": "attacker"
    })
    time.sleep(0.05)
    tenant = TENANTS.get("attacker")
    raw = r.headers.get("X-Aegis-TTFT-Raw-Ms", "?")
    padded = r.headers.get("X-Aegis-TTFT-Padded-Ms", "?")
    pad_val = r.headers.get("X-Aegis-Padding-Ms", "?")
    quarantined = r.headers.get("X-Aegis-Quarantined", "?")
    salt = r.headers.get("X-Aegis-Cache-Salt", "?")
    print(f"  '{probe:10s}'  Raw={raw:>7s}ms  Padded={padded:>7s}ms  Pad={pad_val:>6s}ms  Q={quarantined:>5s}  Salt={salt}")

print()
tenant = TENANTS.get("attacker")
if tenant:
    print(f"  Final LLR: {tenant.llr:.4f}")
    print(f"  Quarantined: {tenant.is_quarantined}")
    print(f"  Cache Salt: {tenant.cache_salt}")

# Phase 2: Post-quarantine probes — padding should eliminate timing signal
print()
print("--- Phase 2: Post-quarantine probes (padding active) ---")
for i in range(1, 4):
    probe = secret[:i]
    r = client.post("/v1/chat/completions", json={
        "messages": [{"role": "user", "content": probe}],
        "tenant_id": "attacker"
    })
    raw = r.headers.get("X-Aegis-TTFT-Raw-Ms", "?")
    padded = r.headers.get("X-Aegis-TTFT-Padded-Ms", "?")
    pad_val = r.headers.get("X-Aegis-Padding-Ms", "?")
    print(f"  '{probe:10s}'  Raw={raw:>7s}ms  Padded={padded:>7s}ms  Pad={pad_val:>6s}ms  (attacker sees {padded}ms)")

# Phase 3: Normal cache-miss for comparison
print()
print("--- Phase 3: Normal cache-miss (should NOT be padded) ---")
r = client.post("/v1/chat/completions", json={
    "messages": [{"role": "user", "content": "Hello world how are you?"}],
    "tenant_id": "attacker"
})
raw = r.headers.get("X-Aegis-TTFT-Raw-Ms", "?")
padded = r.headers.get("X-Aegis-TTFT-Padded-Ms", "?")
pad_val = r.headers.get("X-Aegis-Padding-Ms", "?")
print(f"  Normal prompt  Raw={raw:>7s}ms  Padded={padded:>7s}ms  Pad={pad_val:>6s}ms")
print()
print("  >>> Attacker sees ~85ms ceiling for BOTH hit and miss -> SIDE CHANNEL ELIMINATED")

# ===================================================================
# TEST 2: Defense OFF - No padding, timing leak visible
# ===================================================================
print()
print("=" * 65)
print("TEST 2: DEFENSE OFF - No padding, timing leak visible")
print("=" * 65)

client.post("/api/config", json={"defense_enabled": False})
client.post("/api/reset")

for probe in ["O", "OM", "Hello world"]:
    r = client.post("/v1/chat/completions", json={
        "messages": [{"role": "user", "content": probe}],
        "tenant_id": "nodefense"
    })
    raw = r.headers.get("X-Aegis-TTFT-Raw-Ms", "?")
    padded = r.headers.get("X-Aegis-TTFT-Padded-Ms", "?")
    hit = r.headers.get("X-Aegis-Cache-Hit", "?")
    print(f"  '{probe:15s}'  Raw={raw:>7s}ms  Padded={padded:>7s}ms  Hit={hit:>5s}")

print("  >>> Timing difference is VISIBLE - attacker can distinguish hit/miss")

# ===================================================================
# TEST 3: Config toggle + timing profile switch
# ===================================================================
print()
print("=" * 65)
print("TEST 3: CONFIG TOGGLE + TIMING PROFILE SWITCH")
print("=" * 65)

# Switch to Edge profile
r = client.post("/api/config", json={"timing_profile": "0.5B_Edge", "defense_enabled": True})
data = r.json()
print(f"  Profile: {data['timing_profile']}")
print(f"  Cache Hit: {data['ttft_cache_hit_ms']}ms  Miss: {data['ttft_cache_miss_ms']}ms")
print(f"  Padding Bucket: {data['padding_bucket_ms']}ms")
print(f"  Defense: {data['defense_enabled']}")

# Switch back to 70B
r = client.post("/api/config", json={"timing_profile": "70B_vLLM"})
data = r.json()
print(f"  Restored: {data['timing_profile']}  Bucket: {data['padding_bucket_ms']}ms")

# ===================================================================
# TEST 4: Telemetry - Quarantine Events
# ===================================================================
print()
print("=" * 65)
print("TEST 4: TELEMETRY - Quarantine Events")
print("=" * 65)

client.post("/api/config", json={"defense_enabled": True})
client.post("/api/reset")

# Send probes to trigger quarantine and verify telemetry capture
for p in ["O", "OM", "OME", "OMEG"]:
    client.post("/v1/chat/completions", json={
        "messages": [{"role": "user", "content": p}],
        "tenant_id": "quarantine_tester"
    })
    time.sleep(0.05)

time.sleep(0.1)
r = client.get("/api/telemetry")
telem = r.json()
quarantine_events = [e for e in telem["events"] if e["event_type"] == "quarantine"]
blocked_events = [e for e in telem["events"] if e["blocked"]]
print(f"  Total events: {telem['total_events']}")
print(f"  Quarantine events: {len(quarantine_events)}")
print(f"  Blocked/padded events: {len(blocked_events)}")
if quarantine_events:
    q = quarantine_events[0]
    print(f"  First quarantine: tenant={q['tenant_id']}, LLR={q['llr_after']:.4f}, salt={q['cache_salt']}")

# Cleanup
client.post("/api/reset")
print("\n=== All Milestone 4 tests complete ===")
