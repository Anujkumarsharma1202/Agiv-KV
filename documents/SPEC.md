# 📐 Aegis-KV — Technical & Mathematical Specification (SPEC)

> **Document Version:** 1.0.0  
> **Status:** Production-Grade Technical Specification  
> **Target Audience:** Systems Architects, Cryptographers, and AI Security Researchers  
> **Repository:** [Aegis-KV / Agiv-KV](https://github.com/Anujkumarsharma1202/Agiv-KV)

---

## 1. Mathematical Model: Wald's SPRT Engine

Aegis-KV formulates side-channel timing detection as a sequential hypothesis testing problem using **Abraham Wald's Sequential Probability Ratio Test (SPRT)**. 

### 1.1 Hypothesis Formulation
Let $\{X_1, X_2, \dots, X_n\}$ denote a sequence of independent binary observations from a tenant, where $X_i = 1$ indicates a probe attempt exhibiting a cache-hit timing signal, and $X_i = 0$ indicates a probe attempt experiencing a cache-miss.

$$\begin{aligned}
H_0 &: p = p_0 = 0.05 \quad \text{(Null Hypothesis: Benign tenant; normal cache collisions occur with 5% probability)} \\
H_1 &: p = p_1 = 0.40 \quad \text{(Alternative Hypothesis: Adversary; intentional timing probes yield $\ge 40\%$ hit rate)}
\end{aligned}$$

With operational error bounds:
- **Type I Error Rate ($\alpha$):** $\alpha = 0.01$ ($1.0\%$ False Positive probability)
- **Type II Error Rate ($\beta$):** $\beta = 0.01$ ($1.0\%$ False Negative probability)

### 1.2 Wald Decision Boundaries
The logarithmic decision boundaries $A$ (rejection threshold) and $B$ (acceptance threshold) are defined as:

$$A = \ln \left( \frac{1 - \beta}{\alpha} \right) = \ln \left( \frac{0.99}{0.01} \right) = \ln(99) \approx +4.5951$$

$$B = \ln \left( \frac{\beta}{1 - \alpha} \right) = \ln \left( \frac{0.01}{0.99} \right) = \ln \left( \frac{1}{99} \right) \approx -4.5951$$

### 1.3 Cumulative Log-Likelihood Ratio (LLR) Step Function
For each incoming request $n$:

$$\text{LLR}_n = \text{LLR}_{n-1} + \Delta \text{LLR}_n$$

Where the increment $\Delta \text{LLR}_n$ is derived from the observation state:

$$\Delta \text{LLR}_n = \begin{cases}
\ln \left( \frac{p_1}{p_0} \right) = \ln \left( \frac{0.40}{0.05} \right) = \ln(8) \approx +2.0794 & \text{if } X_n = 1 \text{ (Probe + Cache Hit)} \\
\ln \left( \frac{1 - p_1}{1 - p_0} \right) = \ln \left( \frac{0.60}{0.95} \right) \approx -0.4615 & \text{if } X_n = 0 \text{ (Probe + Cache Miss)} \\
0.00 & \text{if request is classified as non-probing benign}
\end{cases}$$

### 1.4 CUSUM Lower-Bound Flooring
In standard Wald SPRT, negative evidence accumulates downward toward boundary $B = -4.60$. In an adversarial context, an attacker could exploit this by issuing 50 benign queries to drive their LLR deep into negative territory (creating "LLR debt"), allowing them to subsequently execute several probe queries without triggering detection.

To prevent this exploit, Aegis-KV applies **Cumulative Sum (CUSUM) lower-bound clamping**:

$$\text{LLR}_n = \max \left( 0.00, \, \text{LLR}_{n-1} + \Delta \text{LLR}_n \right)$$

This ensures that benign traffic never accumulates negative debt, while any sequence of 3 consecutive cache-hit probes triggers immediate quarantine:

$$3 \times (+2.0794) = +6.2382 \ge A \, (4.5951) \implies \text{\textbf{QUARANTINE TRIGGERED}}$$

### 1.5 Exponential LLR Time-Decay & Auto-Cooldown TTL
To allow legitimate users who inadvertently trigger a false alarm to recover over time, Aegis-KV implements an exponential time decay during idle periods ($\Delta t > 2.0\text{ s}$):

$$\text{LLR}(t) = \max \left( 0.00, \, \text{LLR}_0 \cdot e^{-\lambda \cdot \Delta t} \right)$$

Where $\lambda = \text{llr\_decay\_rate} = 0.05\text{ s}^{-1}$.

Furthermore, quarantined tenants are assigned an expiration timestamp:

$$t_{\text{quarantine\_end}} = t_{\text{trigger}} + \tau_{\text{cooldown}} \quad (\tau_{\text{cooldown}} = 30.0\text{ s})$$

Upon elapsed TTL, `is_quarantined` reverts to `False`, `cache_salt` resets to `"default"`, and `LLR` resets to `0.00`.

---

## 2. Attack Detection Heuristics

Aegis-KV utilizes a **Zero-Oracle Detection Architecture**: it does not know what secret system prompt or RAG context is cached in vLLM. It identifies attacks purely through structural and statistical properties of the prompt sequence.

```
Incoming Request
      │
      ├── 1. Length Heuristic: len(P) <= 3 chars? ──────────────> Flagged as Probe
      ├── 2. Spacing Heuristic: Single-char tokens >= 3? ────────> Flagged as Probe
      ├── 3. Ring Buffer: Prefix extension of prior prompt? ────> Flagged as Probe
      ├── 4. Branching Heuristic: Common prefix >= 2? ──────────> Flagged as Probe
      └── 5. 3-Gram Shingling: Jaccard overlap >= 0.45? ────────> Flagged as Probe
```

### 2.1 Sequential Prefix-Tree Branching Analysis
Each tenant maintains a sliding ring buffer of recent queries: `recent_prompts = deque(maxlen=10)`. An incoming prompt $P_{\text{curr}}$ is evaluated against all prior entries $P_{\text{prev}} \in \text{recent\_prompts}$:

1. **Incremental Extension:**
   $$P_{\text{curr}} \text{ starts with } P_{\text{prev}} \quad \text{and} \quad 0 < |P_{\text{curr}}| - |P_{\text{prev}}| \le 5 \implies \text{Score} = 1.0$$
2. **Branching Candidate Exploration:**
   $$\text{CommonPrefixLength}(P_{\text{curr}}, P_{\text{prev}}) \ge 2 \quad \text{and} \quad ||P_{\text{curr}}| - |P_{\text{prev}}|| \le 2 \implies \text{Score} = 0.85$$
3. **Cold-Start Probe Heuristic:**
   $$\text{Length}(P_{\text{curr}}) \le 3 \implies \text{Score} = 0.0 \quad (\text{Flagged as probe without similarity score})$$

### 2.2 3-Gram Character Shingling (Fuzzy Probe Resistance)
Attackers may attempt to evade prefix detection by injecting whitespace or mutating characters (e.g., `O M E G A` or `O-M-E-G-A`). Aegis-KV neutralizes this via character-level 3-gram extraction:

1. **Normalization:** Remove all whitespace and convert to uppercase: $P^* = \text{clean}(P)$.
2. **Shingle Extraction:**
   $$S(P) = \{ P^*[i : i+3] \mid 0 \le i \le |P^*| - 3 \}$$
3. **Jaccard Similarity:**
   $$J(P_1, P_2) = \frac{|S(P_1) \cap S(P_2)|}{|S(P_1) \cup S(P_2)|}$$
4. **Decision:** If $J(P_{\text{curr}}, P_{\text{prev}}) \ge \theta_{\text{Jaccard}} = 0.45$, the query is classified as a fuzzy side-channel probe.

### 2.3 Global Sybil Multi-Tenant Shield
Sophisticated adversaries rotate client identities (`tenant_id = sybil_1`, `tenant_id = sybil_2`, ...) to circumvent per-tenant rate limits and LLR tracking. Aegis-KV maintains a global cross-tenant ring buffer:

$$\text{GLOBAL\_PROBE\_WINDOW} = \text{deque}(\text{maxlen}=25) \quad \text{storing } (tid_i, P_i)$$

When an incoming query arrives, it is compared against recent queries submitted by **different** tenant IDs ($tid \ne tid_{\text{curr}}$). If a sequential prefix progression is detected across rotating identities, the `GLOBAL_SYBIL_LLR` increments according to Wald's SPRT. Once $\text{GLOBAL\_SYBIL\_LLR} \ge 4.60$, the entire Sybil rotation cluster is neutralized simultaneously.

---

## 3. Mitigation & Timing Physics

### 3.1 Model & Timing Profiles Specification

| Metric / Parameter | Profile: `70B_vLLM` | Profile: `0.5B_Edge` |
|---|---|---|
| **Target HuggingFace Model** | `meta-llama/Llama-3.1-70B-Instruct` | `Qwen/Qwen2.5-0.5B-Instruct` |
| **Inference Engine Spec** | `vLLM v0.6.3 (PagedAttention APC)` | `vLLM v0.6.3 (Local Edge APC)` |
| **Engine Runtime Flags** | `--enable-prefix-caching --block-size 16 --tensor-parallel-size 4` | `--enable-prefix-caching --block-size 16 --dtype float16` |
| **Upstream Cluster Target** | `http://vllm-cluster.internal:8001/v1/chat/completions` | `http://127.0.0.1:8001/v1/chat/completions` |
| **Nominal Cache-Hit TTFT** | $12.0\text{ ms} \pm 2\text{ ms}$ | $3.0\text{ ms} \pm 1\text{ ms}$ |
| **Nominal Cache-Miss TTFT** | $85.0\text{ ms} \pm 2\text{ ms}$ | $18.0\text{ ms} \pm 2\text{ ms}$ |
| **Hit/Miss Threshold ($T$)** | $30.0\text{ ms}$ | $8.0\text{ ms}$ |
| **Constant-Time Bucket Ceiling** | **$85.0\text{ ms}$** | **$20.0\text{ ms}$** |

### 3.2 L4 TCP Socket Jitter Filtering
To prevent network layer jitter from corrupting SPRT signal classification, Aegis-KV applies deterministic jitter deduction:

$$\text{TTFT}_{\text{adjusted}} = \max \left( 1.0, \, \text{TTFT}_{\text{observed}} - \delta_{\text{TCP\_jitter}} \right) \quad (\delta_{\text{TCP\_jitter}} = 3.0\text{ ms})$$

### 3.3 Constant-Time Bucket Padding
When a tenant is quarantined, their responses are padded to the constant-time ceiling:

$$\text{Padding\_Delay} = \max \left( 0.0, \, \text{Bucket\_Ceiling} - \text{TTFT}_{\text{raw}} \right)$$

$$\text{Effective\_TTFT} = \text{TTFT}_{\text{raw}} + \text{Padding\_Delay} = \text{Bucket\_Ceiling}$$

For a 70B model, an attacker experiencing a cache hit ($\sim 12\text{ms}$) receives $+73\text{ms}$ padding, yielding an effective TTFT of $85.0\text{ms}$. An attacker experiencing a cache miss ($\sim 85\text{ms}$) receives $0\text{ms}$ padding, yielding an effective TTFT of $85.0\text{ms}$. The timing delta is reduced to exactly **$0.0\text{ ms}$**.

### 3.4 TOCTOU In-Flight Concurrency Guard
Adversaries may attempt a Time-of-Check to Time-of-Use (TOCTOU) race condition by firing 10 probes simultaneously before the out-of-band worker completes its SPRT update. 

To prevent this, `TenantState.in_flight` tracks active concurrent requests. If:

$$\text{tenant.in\_flight} > \text{max\_in\_flight\_burst} \quad (\text{threshold} = 3)$$

Aegis-KV immediately applies constant-time ceiling padding to the concurrent burst, neutralizing parallel timing extraction.

---

## 4. Complete API & Protocol Reference

### 4.1 `POST /v1/chat/completions` (OpenAI-Compatible L7 Proxy)

#### Request Headers
```http
POST /v1/chat/completions HTTP/1.1
Host: gateway.aegis-kv.internal:8000
Content-Type: application/json
x-tenant-id: tenant_enterprise_42
```

#### Request Payload Schema
```json
{
  "messages": [
    {"role": "user", "content": "Explain differential privacy in machine learning."}
  ],
  "model": "meta-llama/Llama-3.1-70B-Instruct"
}
```

#### Upstream vLLM Forwarding Payload (Constructed by Aegis-KV)
```json
{
  "model": "meta-llama/Llama-3.1-70B-Instruct",
  "messages": [
    {"role": "user", "content": "Explain differential privacy in machine learning."}
  ],
  "max_tokens": 1,
  "extra_body": {
    "cache_salt": "default"
  }
}
```
*(On quarantine, `"cache_salt"` rotates dynamically to `"quarantine_<uuid8>"`).*

#### Response Headers Telemetry Specification
```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Aegis-Hot-Path-Ms: 0.0382
X-Aegis-TTFT-Raw-Ms: 12.18
X-Aegis-TTFT-Padded-Ms: 85.00
X-Aegis-Padding-Ms: 72.82
X-Aegis-Cache-Hit: true
X-Aegis-Tenant-Id: tenant_enterprise_42
X-Aegis-Cache-Salt: quarantine_881964e9
X-Aegis-Quarantined: true
X-Aegis-Defense: true
X-Aegis-Request-Count: 4
X-Aegis-LLR: 6.2383
X-Aegis-vLLM-Block-Alignment: Block #1 (15 Padded + 1 Target Token)
X-Aegis-In-Flight: 0
X-Aegis-Quarantine-TTL-Remaining: 29.8
X-Aegis-Model-Id: meta-llama/Llama-3.1-70B-Instruct
X-Aegis-vLLM-Engine: vLLM v0.6.3 (PagedAttention APC)
```

---

### 4.2 `GET /api/telemetry/stream` (Real-Time SSE Stream)
Streams continuous Server-Sent Events (SSE) serialized from `TelemetryEvent.to_dict()`:

```http
GET /api/telemetry/stream HTTP/1.1
Accept: text/event-stream
```

#### SSE Event Payload Example
```json
data: {
  "timestamp": 1740612345.123,
  "tenant_id": "red_team_attacker",
  "event_type": "quarantine",
  "ttft_raw_ms": 12.24,
  "ttft_adjusted_ms": 9.24,
  "ttft_padded_ms": 85.00,
  "padding_ms": 72.76,
  "llr_before": 4.1588,
  "llr_after": 6.2383,
  "llr_delta": 2.0794,
  "cache_salt": "quarantine_881964e9",
  "hot_path_overhead_ms": 0.0341,
  "shingling_score": 1.0000,
  "prompt_snippet": "OME",
  "is_probe_attempt": true,
  "is_timing_signal": true,
  "is_cache_hit": true,
  "blocked": true,
  "vllm_block_alignment": "Block #1 (15 Padded + 1 Target Token)",
  "quarantine_ttl_remaining_s": 30.0,
  "global_sybil_llr": 0.0,
  "model_id": "meta-llama/Llama-3.1-70B-Instruct",
  "vllm_engine": "vLLM v0.6.3 (PagedAttention APC)",
  "upstream_payload": {
    "model": "meta-llama/Llama-3.1-70B-Instruct",
    "messages": [{"role": "user", "content": "OME"}],
    "max_tokens": 1,
    "extra_body": {"cache_salt": "quarantine_881964e9"}
  }
}
```

---

### 4.3 Control & Benchmark REST API

| Endpoint | Method | Request Payload | Response Summary |
|---|---|---|---|
| `/health` | `GET` | None | Service operational status, active model, and engine flags. |
| `/api/state` | `GET` | None | In-memory directory of all tenant security states and LLRs. |
| `/api/config` | `POST` | `{"defense_enabled": bool, "timing_profile": str, "live_vllm_upstream": bool}` | Dynamic runtime reconfiguration of defense parameters. |
| `/api/reset` | `POST` | None | Wipes all tenant states, LLR sums, and telemetry buffers. |
| `/api/simulate/red-team` | `POST` | `{"mode": "exact" \| "fuzzy" \| "sybil", "tenant_id": str}` | Runs automated multi-step probe benchmark. |
| `/api/simulate/blue-team`| `POST` | `{"count": 40, "tenant_id": str}` | Fires burst of realistic enterprise prompts to verify 0% FPR. |
