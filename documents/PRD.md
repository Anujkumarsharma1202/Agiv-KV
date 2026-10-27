# 🛡️ Aegis-KV — Product Requirements Document (PRD)

> **Document Version:** 1.0.0  
> **Status:** Approved / Production-Ready MVP  
> **Target Problem Statement:** Hack in Hills — PS 04: Securing Adversarial AI Safety Testing Infrastructure  
> **Project Repository:** [Aegis-KV / Agiv-KV](https://github.com/Anujkumarsharma1202/Agiv-KV)

---

## 1. Executive Summary & Problem Statement

### 1.1 Context
In high-throughput, multi-tenant Large Language Model (LLM) serving systems—such as **vLLM**, **TensorRT-LLM**, and **HuggingFace TGI**—memory optimization is paramount. Modern inference engines implement **Automatic Prefix Caching (APC)** and **PagedAttention** to allocate Key-Value (KV) cache memory in discrete physical blocks (typically `block-size=16` tokens). When consecutive or multi-turn requests share an identical prompt prefix, the engine reuses pre-computed KV-cache blocks rather than recomputing attention matrices from scratch.

### 1.2 The Vulnerability: KV-Cache Prefix Timing Side-Channel
While APC dramatically reduces compute and time-to-first-token (TTFT), it introduces a **severe L7 cryptographic timing side-channel**:
1. An adversary submits single-token, character-by-character, or incremental prefix probes (e.g., `O`, `OM`, `OME`, `OMEG`).
2. If the probed prefix matches a victim's proprietary system prompt, sensitive user context, or confidential API token in the shared KV-cache, the request experiences a **Cache-Hit**, resulting in an ultra-low TTFT (**~12 ms** on a 70B parameter model).
3. If the probed prefix does not match, the request experiences a **Cache-Miss**, incurring full prefill latency (**~85 ms** on a 70B parameter model).
4. By measuring the sub-millisecond TTFT delta ($\Delta \approx 73\text{ ms}$), an attacker systematically reconstructs confidential prompts and secrets character-by-character in seconds.

```
[Attacker Request: "O"]     ──(Cache Hit: 12ms)──> Leaked: Match!
[Attacker Request: "OM"]    ──(Cache Hit: 12ms)──> Leaked: Match!
[Attacker Request: "OME"]   ──(Cache Hit: 12ms)──> Leaked: Match!
[Attacker Request: "OMEA"]  ──(Cache Miss: 85ms)─> Leaked: Mismatch!
```

### 1.3 The Economic Dilemma: Why Not Total Isolation?
Traditional enterprise security measures prescribe **Total Isolation** (disabling APC or provisioning dedicated GPU instances per tenant). However:
- Disabling APC increases prefill compute by **300%–500%**.
- Provisioning isolated GPU instances doubles infrastructure cost ($2\times - 4\times$), severely degrading GPU utilization and cluster ROI.

### 1.4 The Aegis-KV Value Proposition
Aegis-KV acts as a **zero-bottleneck, transparent L7 AI Security Gateway** placed directly before the inference cluster. It preserves the performance of shared KV-caching for 99.9% of benign enterprise traffic while dynamically detecting and quarantining side-channel probes with **<0.05ms hot-path overhead** and **0.0% False Positive Rate (FPR)**.

---

## 2. Target Personas

| Persona | Role | Primary Pain Point | Aegis-KV Value |
|---|---|---|---|
| **Cloud AI Infrastructure Engineer** | Manages vLLM inference clusters on Kubernetes/Slurm | Needs maximum GPU throughput via APC but cannot risk cross-tenant cache leakage | Drops into inference ingress as an OpenAI-compatible proxy with $<0.05\text{ ms}$ latency overhead. |
| **Enterprise CISO & AI Security Officer** | Oversees AI governance, compliance, and IP protection | System prompts, proprietary RAG context, and API keys are vulnerable to extraction | Guarantees side-channel suppression via constant-time TTFT padding and dynamic cache salting. |
| **Red-Team & AI Safety Evaluator** | Conducts adversarial LLM audits and penetration testing | Lacks real-time visibility into timing side-channel telemetry and defense boundaries | Live SOC War-Room dashboard, real-time SSE telemetry stream, and upstream vLLM payload inspection. |

---

## 3. Core MVP Features & User Stories

### 3.1 Feature Breakdown

#### F-1: Sub-Millisecond L7 Reverse Proxy Hot-Path
- **Description:** OpenAI-compatible `/v1/chat/completions` proxy built on FastAPI. Implements in-memory $O(1)$ tenant state lookups with zero external database dependencies (eliminates Redis network hop).
- **Latency SLA:** $<0.10\text{ ms}$ hot-path overhead (benchmark achieved: **~0.035 ms**).

#### F-2: Out-of-Band Wald's SPRT & Multi-Vector Probe Analysis
- **Description:** Background worker spawned via `asyncio.create_task()` executes after response transmission. Evaluates:
  1. **Wald's Sequential Probability Ratio Test (SPRT)** ($A \approx 4.60, B \approx -4.60$).
  2. **Sequential Prefix-Tree Branching Detection** (analyzes character extensions in tenant ring buffer).
  3. **3-Gram Character Shingling** (Jaccard similarity threshold $0.45$ to detect space-mutated probes like `O M E G A`).
  4. **Cross-Tenant Sybil Rotation Shield** (`GLOBAL_PROBE_WINDOW` tracking multi-ID rotation attacks).

#### F-3: Automated Quarantine & Constant-Time Bucket Padding
- **Description:** When SPRT LLR crosses the upper boundary ($LLR \ge A = 4.60$):
  1. Rotates tenant's `cache_salt` to `quarantine_<uuid8>` (dynamically isolating KV namespace in vLLM).
  2. Applies constant-time TTFT bucket padding ($85.0\text{ ms}$ for 70B, $20.0\text{ ms}$ for 0.5B) to eliminate any timing signal.
  3. Activates a $30.0\text{s}$ quarantine cooldown TTL and exponential LLR decay for benign recovery.

#### F-4: Real-Time SSE SOC War-Room Dashboard & vLLM Upstream Inspector
- **Description:** Single-page dashboard (`static/index.html`) utilizing Server-Sent Events (SSE) at `/api/telemetry/stream`. Provides live packet streams, LLR gauges, tenant security directories, and an upstream vLLM JSON payload inspector verifying `extra_body.cache_salt` injection.

### 3.2 User Stories
- **US-01:** As a cluster operator, I want to route OpenAI client requests through Aegis-KV without altering client SDK code or query syntax.
- **US-02:** As an enterprise tenant, I want rapid bursts of diverse business queries to pass through unhindered without false quarantine alarms.
- **US-03:** As an adversary attempting character-by-character extraction, my probe sequence must be halted and quarantined within 3 to 4 requests.
- **US-04:** As a security auditor, I want to inspect the exact JSON payload sent to vLLM to confirm `cache_salt` namespace isolation.

---

## 4. Success Metrics & Key Performance Indicators (KPIs)

| Metric | Target SLA | MVP Achieved Result | Verification Method |
|---|---|---|---|
| **Hot-Path Proxy Overhead** | $<0.10\text{ ms}$ | **$0.023\text{ ms} - 0.045\text{ ms}$** | `test_m6.py` Scenario 3 |
| **False Positive Rate (FPR)** | $<0.01\%$ | **$0.0\%$ (0 false alarms on 40 rapid queries)** | `test_m6.py` Scenario 3 |
| **Attack Neutralization Speed** | $\le 5$ probes | **$3 - 4$ character probes** | `test_m4.py` / `test_m6.py` |
| **Post-Defense Timing Delta** | $0.0\text{ ms}$ | **$0.0\text{ ms}$ (Padded ceiling $\sim 85.0\text{ ms}$)** | `test_m4.py` Phase 2 |
| **Fuzzy Mutation Defense** | Catch spaced bypasses | **$100\%$ detected via 3-Gram Shingling** | `test_m6.py` Scenario 4 |
| **Sybil Attack Suppression** | Detect multi-tenant probes | **Halted at probe 3–4 across rotating IDs** | `test_m6.py` Scenario 6 |
| **External Dependencies** | 0 databases / 0 Node.js | **3 pip packages only (`fastapi`, `uvicorn`, `httpx`)** | `requirements.txt` |

---

## 5. Scope & Future Roadmap

### 5.1 In Scope (MVP Release v0.1.0)
- Transparent L7 proxy with OpenAI specification compatibility.
- Calibrated dual timing profiles: `70B_vLLM` (Llama-3.1-70B) and `0.5B_Edge` (Qwen2.5-0.5B).
- Out-of-band Wald SPRT engine with CUSUM flooring at $0.00$.
- 3-Gram character shingling and Global Sybil shield ring buffers.
- Constant-time TTFT bucket padding and TOCTOU in-flight concurrency guards.
- High-density SOC War-Room Dashboard with zero-emoji utilitarian design.
- Dual execution mode: deterministic benchmark physics and live `httpx` vLLM upstream forwarding.

### 5.2 Out of Scope (Current MVP)
- Semantic vector cache protection (e.g., GPTCache / Redis semantic similarity).
- Multi-node distributed state clustering (e.g., Raft consensus across regional gateways).
- Hardware enclave (Confidential GPU / AMD SEV-SNP) physical side-channel isolation.

### 5.3 Future Roadmap
- **v0.2.0:** Kubernetes Ingress Controller & Envoy / Kong WASM Filter plugin.
- **v0.3.0:** Support for AWS Bedrock, Azure OpenAI, and Google Cloud Vertex AI upstream ingress.
- **v0.4.0:** GPU Performance Monitoring Unit (PMU) side-channel correlation engine.
