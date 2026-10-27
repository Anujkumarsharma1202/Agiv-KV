"""Milestone 5: SSE Telemetry Stream + Dashboard Validation."""
import asyncio
import json
import time
from fastapi.testclient import TestClient
from gateway.main import app
from gateway.telemetry import TELEMETRY, TelemetryEvent

client = TestClient(app)

print("=" * 65)
print("MILESTONE 5: SSE TELEMETRY STREAM & DASHBOARD TEST")
print("=" * 65)

# TEST 1: Serve Dashboard HTML
print("\n--- Test 1: Dashboard HTML Endpoint ---")
r = client.get("/")
assert r.status_code == 200
assert "Aegis-KV" in r.text
assert "SPRT Decision Meter" in r.text
assert "Live Packet Stream" in r.text
print("  GET / -> 200 OK (Dashboard loaded with required UI components)")

# TEST 2: Subscriber Registration & Broadcast
print("\n--- Test 2: SSE Broadcast Queue Mechanism ---")
q1 = TELEMETRY.subscribe()
q2 = TELEMETRY.subscribe()
assert len(TELEMETRY.subscribers) >= 2
print(f"  Registered 2 SSE subscriber queues (Active: {len(TELEMETRY.subscribers)})")

test_event = TelemetryEvent(
    tenant_id="m5_test_tenant",
    event_type="probe_detected",
    ttft_raw_ms=12.5,
    ttft_padded_ms=85.0,
    padding_ms=72.5,
    llr_before=2.08,
    llr_after=4.16,
    llr_delta=2.08,
    cache_salt="default",
    hot_path_overhead_ms=0.082,
    prompt_snippet="OME",
    is_probe_attempt=True,
    is_timing_signal=True,
    is_cache_hit=True,
    blocked=True,
)
TELEMETRY.push(test_event)

data1 = q1.get_nowait()
data2 = q2.get_nowait()
assert data1["tenant_id"] == "m5_test_tenant"
assert data1["ttft_padded_ms"] == 85.0
assert data1["padding_ms"] == 72.5
assert data1["blocked"] is True
assert data2["tenant_id"] == "m5_test_tenant"
print("  Broadcast pushed event to all active subscriber queues successfully")

TELEMETRY.unsubscribe(q1)
TELEMETRY.unsubscribe(q2)
print("  Unsubscribed test queues cleanly")

# TEST 3: Live End-to-End Request over Proxy to SSE
print("\n--- Test 3: End-to-End /v1/chat/completions -> SSE Event ---")
client.post("/api/reset")
q_live = TELEMETRY.subscribe()

r = client.post("/v1/chat/completions", json={
    "messages": [{"role": "user", "content": "O"}],
    "tenant_id": "sse_verifier"
})
assert r.status_code == 200

# Give async task a brief moment to run and push to queue
time.sleep(0.08)
assert not q_live.empty()
live_event = q_live.get_nowait()
print(f"  Live SSE Event captured: tenant={live_event['tenant_id']}, raw={live_event['ttft_raw_ms']}ms, LLR={live_event['llr_after']}")
assert live_event["tenant_id"] == "sse_verifier"
assert live_event["ttft_raw_ms"] > 0
TELEMETRY.unsubscribe(q_live)

# TEST 4: Telemetry REST Buffer Check
print("\n--- Test 4: Telemetry REST Endpoint ---")
r = client.get("/api/telemetry")
assert r.status_code == 200
data = r.json()
assert data["total_events"] >= 1
print(f"  GET /api/telemetry -> 200 OK ({data['total_events']} events in ring buffer)")

# Cleanup
client.post("/api/reset")
print("\n=== All Milestone 5 tests passed successfully! ===")
