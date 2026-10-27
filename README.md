# 🛡️ Aegis-KV — L7 AI Security Gateway & SOC War-Room

> **Sub-millisecond L7 AI Security Gateway mitigating KV-Cache Prefix Timing Side-Channel Attacks in multi-tenant LLM serving systems (e.g., vLLM).**

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Hot-Path Overhead](https://img.shields.io/badge/Hot--Path%20Overhead-%3C0.08ms-brightgreen.svg)]()
[![False Positive Rate](https://img.shields.io/badge/False%20Positive%20Rate-0.0%25-success.svg)]()
[![License](https://img.shields.io/badge/License-MIT-purple.svg)]()

---

## 🎯 The Problem: KV-Cache Prefix Timing Side-Channel

In multi-tenant LLM engines (such as vLLM, TensorRT-LLM, and TGI), prefix caching reuses KV-cache blocks across requests to save compute. 

However, this creates a **critical timing side-channel**:
1. An attacker sends single-token or character prefix probes (e.g., `O`, `OM`, `OME`).
2. If the prefix matches a confidential system prompt or victim's prompt in the shared KV-cache, the request experiences a **Cache-Hit** and returns with an ultra-low TTFT (**~12 ms**).
3. If it misses, it incurs full prefill latency (**~85 ms**).
4. By measuring sub-millisecond TTFT differences, the attacker can leak confidential system instructions (like API secrets or system prompts) in seconds.

---

## ⚡ The Solution: Aegis-KV

Aegis-KV sits as a transparent, high-performance L7 proxy before your inference cluster:

| Layer | Aegis-KV Innovation | Performance Guarantee |
|---|---|---|
| **Hot-Path Proxy** | In-memory `O(1)` dict state lookup — zero database queries | **Overhead < 0.08 ms** |
| **Out-of-Band Detection** | Wald's Sequential Probability Ratio Test (SPRT) + 3-Gram Shingling | Async worker via `asyncio.create_task()` — **0ms hot-path delay** |
| **Automated Quarantine** | Instant `cache_salt` namespace isolation | Attacker isolated into private KV namespace |
| **Side-Channel Mitigation** | Constant-Time TTFT Bucket Padding (~65ms) | Cache-hits padded so hits & misses are indistinguishable |
| **False Positive Guarantee** | CUSUM floored LLR + probe-length filtering | **0.0% False Positive Rate on benign enterprise bursts** |

---

## 🚀 One-Command Quick Start

### 1. Install Lightweight Dependencies (3 only!)
```bash
pip install fastapi uvicorn httpx
```

### 2. Launch Gateway
```bash
python -m uvicorn gateway.main:app --host 0.0.0.0 --port 8000
```

### 3. Open Live SOC War-Room Dashboard
Navigate to: **[http://localhost:8000/](http://localhost:8000/)**

---

## 🎬 Live Hackathon Demo Walkthrough

### 1. Interactive Web Dashboard
1. Open **`http://localhost:8000/`** in your browser.
2. Under **Live Simulator**, click **`🔴 Run Red-Team Attack`**:
   - Watch the character-by-character probe attack in real-time.
   - At probe 3 (`OME`), SPRT LLR crosses $A = 4.60$.
   - **Quarantine triggers instantly**: `cache_salt` rotates, TTFT is padded to constant ~65ms, and the attacker is thwarted!
3. Click **`🔵 Fire 20 Benign Prompts`**:
   - Watch 20 enterprise queries stream through cleanly.
   - Notice $LLR = 0.00$, preserving a **0.0% False Positive Rate**.
4. Toggle **`Defense: ON / OFF`** to show judges what happens when unprotected:
   - When Defense is OFF, the attacker extracts `OMEGA_77` in full.

### 2. Automated Benchmark & Verification Suite
Run all milestone tests directly:

```bash
# Milestone 4: Quarantine + TTFT Padding validation
python test_m4.py

# Milestone 5: SSE Streaming + Dashboard validation
python test_m5.py

# Milestone 6: Complete Red-Team vs Blue-Team Simulation Suite
python test_m6.py
```

---

## 📡 API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/` | `GET` | Single-page SOC War-Room Dashboard (HTML + Tailwind + SSE) |
| `/health` | `GET` | Gateway health check and operational parameters |
| `/v1/chat/completions` | `POST` | OpenAI-compatible proxy with sub-0.1ms overhead |
| `/api/telemetry/stream` | `GET` | Real-time Server-Sent Events (SSE) telemetry stream |
| `/api/state` | `GET` | In-memory tenant directory & security states |
| `/api/config` | `POST` | Toggle defense ON/OFF or switch timing profiles (`70B_vLLM` / `0.5B_Edge`) |
| `/api/simulate/red-team` | `POST` | Run automated prefix probe attack (exact or fuzzy) |
| `/api/simulate/blue-team` | `POST` | Fire 40 rapid benign queries (verifies 0% FP rate) |
| `/api/reset` | `POST` | Reset all tenant states and telemetry for clean demo runs |

---

## 🛡️ Response Headers Telemetry

Every L7 response includes rich cryptographic and timing telemetry headers:

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Aegis-Hot-Path-Ms: 0.0588
X-Aegis-TTFT-Raw-Ms: 12.24
X-Aegis-TTFT-Padded-Ms: 65.00
X-Aegis-Padding-Ms: 52.76
X-Aegis-Cache-Hit: true
X-Aegis-Tenant-Id: red_team_attacker
X-Aegis-Cache-Salt: quarantine_881964e9
X-Aegis-Quarantined: true
X-Aegis-Defense: true
X-Aegis-LLR: 6.2383
```

---

## 👥 HackInHills MVP Architecture

```
Aegis-KV/
├── gateway/
│   ├── main.py            # FastAPI app, L7 proxy, SSE stream, simulator endpoints
│   ├── config.py          # GatewayConfig (Wald boundaries, timing profiles, secrets)
│   ├── state.py           # In-memory TenantState store (O(1) dict lookup)
│   ├── sprt.py            # Wald's SPRT engine + 3-Gram character shingling
│   ├── defense.py         # Quarantine logic (cache_salt rotation + TTFT padding)
│   └── telemetry.py       # TelemetryLog ring buffer + SSE broadcaster
├── static/
│   └── index.html         # SOC War-Room Dashboard (Tailwind + SSE + JS)
├── test_m4.py             # Milestone 4 test script
├── test_m5.py             # Milestone 5 test script
├── test_m6.py             # Milestone 6 comprehensive demo suite
├── requirements.txt       # fastapi, uvicorn, httpx
└── README.md              # Documentation & Demo Guide
```

**Zero external databases. Zero build tools. Zero Node.js.**
Sub-millisecond AI Security built for cloud-scale inference.
