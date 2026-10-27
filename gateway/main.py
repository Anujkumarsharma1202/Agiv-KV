"""
Aegis-KV Gateway — FastAPI Application.

Serves:
  GET  /              → SOC Dashboard (static/index.html)
  GET  /health        → Health check
  POST /v1/chat/completions → L7 proxy with O(1) tenant lookup + mock LLM
  GET  /api/state     → All tenant states (for dashboard)
  GET  /api/telemetry → Recent telemetry events
  POST /api/config    → Toggle defense, switch timing profile
  POST /api/reset     → Reset all tenant state (for demo)
"""

from __future__ import annotations

import asyncio
import random
import time
import uuid
import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from gateway.config import GATEWAY_CONFIG
from gateway.defense import compute_padding_delay_ms, maybe_quarantine
from gateway.sprt import (
    compute_adjusted_ttft,
    compute_sprt_update,
    compute_vllm_block_alignment,
    detect_sybil_probe_pattern,
    compute_sybil_sprt_update,
)
from gateway.state import (
    TENANTS,
    TenantState,
    get_or_create_tenant,
    reset_all_tenants,
    GLOBAL_PROBE_WINDOW,
    get_global_sybil_llr,
    set_global_sybil_llr,
    update_global_sybil_llr,
    record_global_probe,
)
from gateway.telemetry import TELEMETRY, TelemetryEvent

# ── Paths ────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"

# ── FastAPI App ──────────────────────────────────────────────────────────
app = FastAPI(
    title="Aegis-KV",
    description="L7 AI Security Gateway — KV-Cache Side-Channel Defense",
    version="0.1.0",
)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ── Dashboard ────────────────────────────────────────────────────────────
@app.get("/", tags=["Dashboard"])
async def serve_dashboard() -> FileResponse:
    """Serve the single-page SOC War-Room dashboard."""
    return FileResponse(str(STATIC_DIR / "index.html"))


# ── Health Check ─────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health_check() -> JSONResponse:
    """System health check."""
    cfg = GATEWAY_CONFIG
    return JSONResponse(content={
        "status": "ok",
        "service": "Aegis-KV",
        "version": "0.1.0",
        "engine": "In-Memory O(1) + SPRT Out-of-Band",
        "defense_enabled": cfg.defense_enabled,
        "timing_profile": cfg.timing_profile,
        "sprt_upper_boundary": round(cfg.sprt_upper_boundary, 4),
        "tenants_tracked": len(TENANTS),
    })


# ── Out-of-Band Analysis Worker ─────────────────────────────────────────
async def _analyze_request(
    tenant: TenantState,
    prompt: str,
    ttft_raw_ms: float,
    ttft_padded_ms: float,
    overhead_ms: float,
    is_cache_hit: bool,
    was_padded: bool,
    vllm_block: str = "",
) -> None:
    """
    Background SPRT + Shingling analysis + auto-quarantine + Global Sybil Shield.
    Fired via asyncio.create_task() AFTER the response is returned.
    Zero impact on hot-path latency.
    """
    cfg = GATEWAY_CONFIG

    # 1. L4 TCP jitter removal
    adjusted_ttft = compute_adjusted_ttft(ttft_raw_ms, cfg)

    # 2. SPRT update with Zero-Oracle dynamic probe detection (per-tenant)
    llr_before = tenant.llr
    llr_delta, is_probe_attempt, is_timing_signal, similarity_score = compute_sprt_update(
        adjusted_ttft, prompt, tenant.recent_prompts, cfg
    )

    # 3. Global Sybil / Multi-Tenant Rotation Detection (Upgrade 1)
    sybil_llr_delta, is_sybil_attempt, is_sybil_timing, sybil_sim = compute_sybil_sprt_update(
        adjusted_ttft, tenant.tenant_id, prompt, GLOBAL_PROBE_WINDOW, cfg
    )

    if is_sybil_attempt and cfg.defense_enabled:
        update_global_sybil_llr(sybil_llr_delta)

    # Apply LLR update with floor at 0.0 (CUSUM-style)
    tenant.llr = max(0.0, tenant.llr + llr_delta)

    if is_timing_signal or (is_sybil_attempt and is_sybil_timing):
        tenant.probe_count += 1

    # 4. Auto-quarantine check (affects FUTURE requests)
    newly_quarantined = False
    if cfg.defense_enabled:
        # Per-tenant Wald boundary A
        newly_quarantined = maybe_quarantine(tenant, cfg)

        # Global Sybil Shield Wald boundary A
        if not tenant.is_quarantined and get_global_sybil_llr() >= cfg.sprt_upper_boundary:
            tenant.is_quarantined = True
            tenant.quarantined_until = time.time() + cfg.quarantine_ttl_sec
            tenant.cache_salt = f"quarantine_{uuid.uuid4().hex[:8]}"
            newly_quarantined = True

    # 5. Classify event type
    effective_probe = is_probe_attempt or is_sybil_attempt
    effective_timing = is_timing_signal or (is_sybil_attempt and is_sybil_timing)

    if newly_quarantined:
        event_type = "quarantine"
    elif effective_probe and effective_timing:
        event_type = "probe_detected"
    elif effective_probe:
        event_type = "probe_miss"
    else:
        event_type = "benign"

    # 6. Push telemetry event
    event = TelemetryEvent(
        tenant_id=tenant.tenant_id,
        event_type=event_type,
        ttft_raw_ms=ttft_raw_ms,
        ttft_adjusted_ms=adjusted_ttft,
        ttft_padded_ms=ttft_padded_ms,
        padding_ms=max(0.0, ttft_padded_ms - ttft_raw_ms),
        llr_before=llr_before,
        llr_after=tenant.llr,
        llr_delta=llr_delta,
        cache_salt=tenant.cache_salt,
        hot_path_overhead_ms=overhead_ms,
        shingling_score=max(similarity_score, sybil_sim),
        prompt_snippet=prompt[:40],
        is_probe_attempt=effective_probe,
        is_timing_signal=effective_timing,
        is_cache_hit=is_cache_hit,
        blocked=was_padded,
        vllm_block_alignment=vllm_block,
        quarantine_ttl_remaining_s=tenant.quarantine_ttl_remaining,
        global_sybil_llr=get_global_sybil_llr(),
    )
    TELEMETRY.push(event)


# ── Core Proxy Logic (Shared between HTTP proxy and Simulators) ───────
async def execute_core_proxy(tenant_id: str, user_prompt: str) -> dict[str, Any]:
    """
    Core L7 proxy execution pipeline:
      1. O(1) in-memory tenant lookup (<0.1ms).
      2. Synchronous hot-path probe recording + TOCTOU concurrency counter.
      3. LLR exponential decay & Quarantine Auto-Cooldown TTL check.
      4. Global Sybil Anomaly Shield check.
      5. Simulate LLM TTFT with prefix cache-hit / cache-miss timing.
      6. Apply constant-time bucket padding if quarantined OR concurrency burst (>3 in flight).
      7. Fire out-of-band SPRT + shingling + auto-quarantine via asyncio.create_task().
      8. Construct OpenAI-compatible payload and telemetry headers.
    """
    cfg = GATEWAY_CONFIG
    t_start = time.perf_counter_ns()

    tenant = get_or_create_tenant(tenant_id)
    tenant.request_count += 1
    tenant.in_flight += 1

    prompt_stripped = user_prompt.strip()

    # Upgrade 2: Synchronous hot-path append (O(1) <0.005ms)
    tenant.record_prompt(prompt_stripped)
    record_global_probe(tenant_id, prompt_stripped)

    # Upgrade 3: Time-decay & Auto-cooldown TTL check
    tenant.check_cooldown_and_decay(cfg)

    # Upgrade 1: Hot-path Sybil shield check (if Global Sybil LLR already tripped)
    if cfg.defense_enabled and get_global_sybil_llr() >= cfg.sprt_upper_boundary:
        is_sybil_hot, _ = detect_sybil_probe_pattern(tenant_id, prompt_stripped, GLOBAL_PROBE_WINDOW, cfg.jaccard_threshold)
        if is_sybil_hot and not tenant.is_quarantined:
            tenant.is_quarantined = True
            tenant.quarantined_until = time.time() + cfg.quarantine_ttl_sec
            tenant.cache_salt = f"quarantine_{uuid.uuid4().hex[:8]}"

    # Upgrade 4: vLLM PagedAttention 16-token block alignment
    vllm_block = compute_vllm_block_alignment(prompt_stripped)

    t_pre_llm = time.perf_counter_ns()
    overhead_before_ms = (t_pre_llm - t_start) / 1_000_000

    try:
        secret = cfg.hidden_secret
        # Cache-hit check
        is_cache_hit = (
            tenant.cache_salt == "default"
            and len(prompt_stripped) > 0
            and len(prompt_stripped) <= len(secret)
            and secret.startswith(prompt_stripped)
        )

        jitter = random.uniform(-2.0, 2.0)
        if is_cache_hit:
            simulated_ttft_ms = cfg.ttft_cache_hit_ms + jitter
        else:
            simulated_ttft_ms = cfg.ttft_cache_miss_ms + jitter
        simulated_ttft_ms = max(1.0, simulated_ttft_ms)

        tenant.record_ttft(simulated_ttft_ms)
        await asyncio.sleep(simulated_ttft_ms / 1000.0)

        # Upgrade 2: TOCTOU race condition guard (concurrency limiter > 3)
        t_defense_start = time.perf_counter_ns()
        is_concurrent_burst = tenant.in_flight > cfg.max_in_flight_burst
        should_pad = cfg.defense_enabled and (tenant.is_quarantined or is_concurrent_burst)

        padding_ms = 0.0
        was_padded = False
        if should_pad:
            padding_ms = compute_padding_delay_ms(simulated_ttft_ms, cfg)
        t_defense_end = time.perf_counter_ns()
        overhead_after_ms = (t_defense_end - t_defense_start) / 1_000_000
        total_overhead_ms = overhead_before_ms + overhead_after_ms

        if should_pad and padding_ms > 0:
            await asyncio.sleep(padding_ms / 1000.0)
            was_padded = True

        effective_ttft_ms = simulated_ttft_ms + padding_ms

        completion_id = f"chatcmpl-aegis-{uuid.uuid4().hex[:12]}"
        response_content = (
            f"[Aegis-KV Mock] Processed prompt ({len(prompt_stripped)} chars). "
            f"TTFT: {effective_ttft_ms:.1f}ms [{vllm_block}]"
        )

        response_body = {
            "id": completion_id,
            "object": "chat.completion",
            "model": f"aegis-kv-mock-{cfg.timing_profile}",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": response_content,
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": len(prompt_stripped),
                "completion_tokens": len(response_content),
                "total_tokens": len(prompt_stripped) + len(response_content),
            },
        }

        asyncio.create_task(
            _analyze_request(
                tenant, prompt_stripped, simulated_ttft_ms,
                effective_ttft_ms, total_overhead_ms, is_cache_hit, was_padded,
                vllm_block,
            )
        )

        headers = {
            "X-Aegis-Hot-Path-Ms": f"{total_overhead_ms:.4f}",
            "X-Aegis-TTFT-Raw-Ms": f"{simulated_ttft_ms:.2f}",
            "X-Aegis-TTFT-Padded-Ms": f"{effective_ttft_ms:.2f}",
            "X-Aegis-Padding-Ms": f"{padding_ms:.2f}",
            "X-Aegis-Cache-Hit": str(is_cache_hit).lower(),
            "X-Aegis-Tenant-Id": tenant_id,
            "X-Aegis-Cache-Salt": tenant.cache_salt,
            "X-Aegis-Quarantined": str(tenant.is_quarantined).lower(),
            "X-Aegis-Defense": str(cfg.defense_enabled).lower(),
            "X-Aegis-Request-Count": str(tenant.request_count),
            "X-Aegis-LLR": f"{tenant.llr:.4f}",
            "X-Aegis-vLLM-Block-Alignment": vllm_block,
            "X-Aegis-In-Flight": str(tenant.in_flight),
            "X-Aegis-Quarantine-TTL-Remaining": f"{tenant.quarantine_ttl_remaining:.1f}",
        }

        return {
            "response_body": response_body,
            "headers": headers,
            "total_overhead_ms": total_overhead_ms,
            "simulated_ttft_ms": simulated_ttft_ms,
            "effective_ttft_ms": effective_ttft_ms,
            "padding_ms": padding_ms,
            "is_cache_hit": is_cache_hit,
            "was_padded": was_padded,
            "vllm_block_alignment": vllm_block,
        }
    finally:
        tenant.in_flight = max(0, tenant.in_flight - 1)


# ── L7 Proxy: /v1/chat/completions ──────────────────────────────────────
@app.post("/v1/chat/completions", tags=["Proxy"])
async def chat_completions(request: Request) -> JSONResponse:
    """
    L7 proxy endpoint (OpenAI-compatible).
    Hot-path: <0.1ms overhead tenant lookup + mock vLLM + TTFT padding.
    """
    body: dict[str, Any] = await request.json()
    tenant_id = (
        request.headers.get("x-tenant-id")
        or body.get("tenant_id")
        or "anonymous"
    )
    messages: list[dict[str, str]] = body.get("messages", [])
    user_prompt = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            user_prompt = msg.get("content", "")
            break

    result = await execute_core_proxy(tenant_id, user_prompt)
    return JSONResponse(content=result["response_body"], headers=result["headers"])


# ── API: Tenant State (for dashboard) ────────────────────────────────────
@app.get("/api/state", tags=["API"])
async def get_all_state() -> JSONResponse:
    """Return all tenant states for the dashboard."""
    states = {}
    for tid, tenant in TENANTS.items():
        states[tid] = {
            "tenant_id": tenant.tenant_id,
            "llr": round(tenant.llr, 4),
            "request_count": tenant.request_count,
            "probe_count": tenant.probe_count,
            "in_flight": tenant.in_flight,
            "is_quarantined": tenant.is_quarantined,
            "quarantined_until": tenant.quarantined_until,
            "quarantine_ttl_remaining_s": tenant.quarantine_ttl_remaining,
            "cache_salt": tenant.cache_salt,
            "avg_ttft_ms": round(
                sum(tenant.ttft_history) / len(tenant.ttft_history), 2
            ) if tenant.ttft_history else 0.0,
            "last_ttft_ms": round(tenant.ttft_history[-1], 2)
                if tenant.ttft_history else 0.0,
        }
    return JSONResponse(content={
        "tenants": states,
        "global_sybil_llr": round(get_global_sybil_llr(), 4),
        "config": {
            "defense_enabled": GATEWAY_CONFIG.defense_enabled,
            "timing_profile": GATEWAY_CONFIG.timing_profile,
            "sprt_upper_boundary": round(GATEWAY_CONFIG.sprt_upper_boundary, 4),
            "sprt_lower_boundary": round(GATEWAY_CONFIG.sprt_lower_boundary, 4),
            "hidden_secret_length": len(GATEWAY_CONFIG.hidden_secret),
            "quarantine_ttl_sec": GATEWAY_CONFIG.quarantine_ttl_sec,
            "llr_decay_rate": GATEWAY_CONFIG.llr_decay_rate,
            "global_sybil_llr": round(get_global_sybil_llr(), 4),
        },
    })


# ── API: Telemetry (for dashboard) ───────────────────────────────────────
@app.get("/api/telemetry", tags=["API"])
async def get_telemetry() -> JSONResponse:
    """Return recent telemetry events."""
    return JSONResponse(content={
        "events": TELEMETRY.recent(100),
        "total_events": len(TELEMETRY.events),
    })


# ── API: Telemetry SSE Stream (for real-time dashboard) ─────────────────
@app.get("/api/telemetry/stream", tags=["API"])
async def telemetry_stream(request: Request) -> StreamingResponse:
    """
    Server-Sent Events (SSE) live telemetry stream.
    Pushes each TelemetryEvent in real-time as JSON to connected dashboards.
    """
    queue = TELEMETRY.subscribe()

    async def event_generator():
        try:
            # Initial connection handshake event
            yield f"data: {json.dumps({'event_type': 'connected', 'timestamp': time.time()})}\n\n"
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=10.0)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            TELEMETRY.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── API: Config Toggle (for dashboard) ──────────────────────────────────
@app.post("/api/config", tags=["API"])
async def update_config(request: Request) -> JSONResponse:
    """
    Toggle defense and switch timing profiles.
    Body: {"defense_enabled": bool, "timing_profile": "70B_vLLM"|"0.5B_Edge"}
    """
    body: dict[str, Any] = await request.json()
    cfg = GATEWAY_CONFIG

    if "defense_enabled" in body:
        cfg.defense_enabled = bool(body["defense_enabled"])

    if "timing_profile" in body:
        profile = body["timing_profile"]
        if profile in ("70B_vLLM", "0.5B_Edge"):
            cfg.apply_timing_profile(profile)

    return JSONResponse(content={
        "status": "updated",
        "defense_enabled": cfg.defense_enabled,
        "timing_profile": cfg.timing_profile,
        "padding_bucket_ms": cfg.padding_bucket_ms,
        "ttft_cache_hit_ms": cfg.ttft_cache_hit_ms,
        "ttft_cache_miss_ms": cfg.ttft_cache_miss_ms,
    })


# ── API: Reset (for demo) ───────────────────────────────────────────────
@app.post("/api/reset", tags=["API"])
async def reset_state() -> JSONResponse:
    """Reset all tenant states and telemetry. Used for demo resets."""
    reset_all_tenants()
    TELEMETRY.clear()
    return JSONResponse(content={"status": "reset", "tenants_cleared": True})


# ── API: Simulators (for one-click Demo & Benchmarking) ───────────────────
@app.post("/api/simulate/red-team", tags=["Simulation"])
async def simulate_red_team(request: Request) -> JSONResponse:
    """
    Run automated Red-Team prefix probe attack.
    Supports:
      - mode='exact': Single tenant character-by-character extraction.
      - mode='fuzzy': Space-mutated probe testing 3-gram shingling.
      - mode='sybil': Multi-tenant rotating ID attack testing Global Sybil Shield.
    """
    try:
        body: dict[str, Any] = await request.json()
    except Exception:
        body = {}

    tenant_id = body.get("tenant_id", "red_team_simulator")
    mode = body.get("mode", "exact")
    cfg = GATEWAY_CONFIG
    secret = cfg.hidden_secret

    if mode == "fuzzy":
        fuzzy_prompt = "O M E G A _ 7 7"
        res = await execute_core_proxy(tenant_id, fuzzy_prompt)
        await asyncio.sleep(0.04)  # Allow background worker
        tenant = get_or_create_tenant(tenant_id)
        return JSONResponse(content={
            "status": "completed",
            "mode": "fuzzy",
            "prompt": fuzzy_prompt,
            "target_secret": secret,
            "quarantined": tenant.is_quarantined,
            "final_llr": round(tenant.llr, 4),
            "effective_ttft_ms": round(res["effective_ttft_ms"], 2),
            "vllm_block_alignment": res.get("vllm_block_alignment", ""),
        })

    if mode == "sybil":
        steps = []
        recovered = ""
        quarantined = False
        last_tenant = None

        for i in range(1, len(secret) + 1):
            tid = f"sybil_bot_{i}"
            probe = secret[:i]
            res = await execute_core_proxy(tid, probe)
            await asyncio.sleep(0.03)  # Tick for background analysis
            last_tenant = get_or_create_tenant(tid)

            is_quarantined_now = last_tenant.is_quarantined or (get_global_sybil_llr() >= cfg.sprt_upper_boundary)
            step_info = {
                "probe": probe,
                "tenant_id": tid,
                "raw_ttft_ms": round(res["simulated_ttft_ms"], 2),
                "effective_ttft_ms": round(res["effective_ttft_ms"], 2),
                "padding_ms": round(res["padding_ms"], 2),
                "is_cache_hit": res["is_cache_hit"],
                "llr": round(last_tenant.llr, 4),
                "global_sybil_llr": round(get_global_sybil_llr(), 4),
                "quarantined": is_quarantined_now,
                "salt": last_tenant.cache_salt,
                "vllm_block_alignment": res.get("vllm_block_alignment", ""),
            }
            steps.append(step_info)
            recovered = probe

            if is_quarantined_now and cfg.defense_enabled:
                quarantined = True
                break

        return JSONResponse(content={
            "status": "completed",
            "mode": "sybil",
            "target_secret": secret,
            "extracted_secret": recovered,
            "fully_leaked": (recovered == secret and not quarantined),
            "quarantined": quarantined,
            "defense_enabled": cfg.defense_enabled,
            "final_llr": round(last_tenant.llr, 4) if last_tenant else 0.0,
            "global_sybil_llr": round(get_global_sybil_llr(), 4),
            "steps_count": len(steps),
            "steps": steps,
        })

    # Exact character-by-character prefix probe
    steps = []
    recovered = ""
    for i in range(1, len(secret) + 1):
        probe = secret[:i]
        res = await execute_core_proxy(tenant_id, probe)
        await asyncio.sleep(0.02)  # Tick for background analysis
        tenant = get_or_create_tenant(tenant_id)

        step_info = {
            "probe": probe,
            "raw_ttft_ms": round(res["simulated_ttft_ms"], 2),
            "effective_ttft_ms": round(res["effective_ttft_ms"], 2),
            "padding_ms": round(res["padding_ms"], 2),
            "is_cache_hit": res["is_cache_hit"],
            "llr": round(tenant.llr, 4),
            "quarantined": tenant.is_quarantined,
            "salt": tenant.cache_salt,
            "vllm_block_alignment": res.get("vllm_block_alignment", ""),
        }
        steps.append(step_info)

        if tenant.is_quarantined and cfg.defense_enabled:
            recovered = probe
            break
        else:
            recovered = probe

    tenant = get_or_create_tenant(tenant_id)
    return JSONResponse(content={
        "status": "completed",
        "mode": "exact",
        "target_secret": secret,
        "extracted_secret": recovered,
        "fully_leaked": (recovered == secret and not tenant.is_quarantined),
        "quarantined": tenant.is_quarantined,
        "defense_enabled": cfg.defense_enabled,
        "final_llr": round(tenant.llr, 4),
        "steps_count": len(steps),
        "steps": steps,
    })


@app.post("/api/simulate/blue-team", tags=["Simulation"])
async def simulate_blue_team(request: Request) -> JSONResponse:
    """
    Run Blue-Team benign prompt burst (40 realistic customer queries).
    Verifies 0% False Positive Rate (LLR stays 0.00, no quarantine).
    """
    try:
        body: dict[str, Any] = await request.json()
    except Exception:
        body = {}

    count = int(body.get("count", 40))
    tenant_prefix = body.get("tenant_id", "blue_customer")

    benign_prompts = [
        "What is the capital of France and what are its best landmarks?",
        "Explain how differential privacy protects sensitive datasets in machine learning.",
        "Write a Python function to compute the Fibonacci sequence efficiently using memoization.",
        "Summarize the key architectural principles of resilient Kubernetes clusters.",
        "What are the security implications of shared cache in multi-tenant cloud GPUs?",
        "Can you recommend a recipe for authentic Neapolitan pizza dough?",
        "Explain the difference between TCP BBR and CUBIC congestion control algorithms.",
        "How do transformers utilize multi-head self-attention mechanisms in natural language processing?",
        "What is Wald's Sequential Probability Ratio Test used for in statistical quality control?",
        "Help me debug an asynchronous event loop timeout in FastAPI web applications.",
        "What are the core benefits and implementation steps of zero-trust network architectures?",
        "Describe the role of key-value caches in accelerating large language model inference.",
        "How can enterprise systems mitigate timing side-channel attacks on shared infrastructure?",
        "Give me an overview of quantum-resistant post-quantum cryptographic standards like Kyber.",
        "Explain the principles behind rate-limiting algorithms like token bucket and leaky bucket.",
        "What is the mathematical definition and significance of the Jaccard similarity coefficient?",
        "How does virtual memory paging work in high-throughput inference engines like vLLM?",
        "Draft a step-by-step incident response plan for cloud infrastructure security breaches.",
        "Explain how HTTP/2 multiplexing improves web application latency over HTTP/1.1.",
        "Provide best practices for securing internal REST APIs with OAuth2 and JWT in production.",
    ]

    total_overhead = 0.0
    for i in range(count):
        prompt = benign_prompts[i % len(benign_prompts)]
        tid = f"{tenant_prefix}_{(i % 3) + 1}"
        res = await execute_core_proxy(tid, prompt)
        total_overhead += res["total_overhead_ms"]
        await asyncio.sleep(0.005)

    await asyncio.sleep(0.05)

    fpr_count = 0
    max_llr = 0.0
    for i in range(1, 4):
        t = get_or_create_tenant(f"{tenant_prefix}_{i}")
        if t.is_quarantined:
            fpr_count += 1
        if t.llr > max_llr:
            max_llr = t.llr

    return JSONResponse(content={
        "status": "completed",
        "prompts_sent": count,
        "false_positives": fpr_count,
        "false_positive_rate": 0.0 if fpr_count == 0 else (fpr_count / count) * 100,
        "max_llr": round(max_llr, 4),
        "quarantined": fpr_count > 0,
        "avg_hot_path_overhead_ms": round(total_overhead / count, 4),
    })
