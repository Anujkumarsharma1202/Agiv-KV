"""
Aegis-KV — Wald's SPRT Engine + Dynamic Sequential Probe Detection.

Zero-Oracle Architecture:
  A real L7 gateway does NOT know what secret is cached in vLLM.
  Instead of comparing against a hardcoded target secret or skipping prompts
  arbitrarily by length, this engine detects timing attacks dynamically by analyzing:
    1. Inter-request sequential prefix extensions (e.g. O -> OM -> OME -> OMEG...)
    2. Branching prefix mutations (e.g. testing OMEA, OMEB, OMEC...)
    3. Cold-start short probe heuristics (<= 3 chars)
    4. Spaced/fuzzy character mutations (e.g. "O M E G A") via 3-gram Jaccard overlap
       against the tenant's own recent prompt ring buffer.

SPRT Math (Wald's Sequential Probability Ratio Test):
  H0: probe_rate = p0 (5%, normal noise)
  H1: probe_rate = p1 (40%, active attacker)
  LLR += log(p1/p0)           if probe attempt & cache-hit timing signal (<30ms)
  LLR += log((1-p1)/(1-p0))   if probe attempt but cache-miss (>30ms)
  LLR is floored at 0.0 (CUSUM-style reset — benign evidence doesn't accumulate)
  Quarantine triggered when LLR >= A = ln((1-β)/α) ≈ 4.5951
"""

from __future__ import annotations

import math
from typing import Sequence

from gateway.config import GatewayConfig


# ── TCP Jitter Filtering ────────────────────────────────────────────────

def compute_adjusted_ttft(observed_ttft_ms: float, config: GatewayConfig) -> float:
    """
    L4 TCP socket jitter removal.
    Net_Adjusted_TTFT = Observed_TTFT - TCP_Jitter_Estimate
    """
    adjusted = observed_ttft_ms - config.tcp_jitter_estimate_ms
    return max(1.0, adjusted)  # Floor at 1ms (can't be negative)


# ── 3-Gram Character Shingling (Jaccard Similarity) ─────────────────────

def _extract_trigrams(text: str) -> set[str]:
    """
    Extract character-level 3-grams after stripping whitespace and uppercasing.
    "O M E G A" -> "OMEGA" -> {"OME", "MEG", "EGA"}
    """
    cleaned = text.replace(" ", "").replace("\t", "").replace("\n", "").upper()
    if len(cleaned) < 3:
        return {cleaned} if cleaned else set()
    return {cleaned[i : i + 3] for i in range(len(cleaned) - 2)}


def compute_jaccard_3gram(text1: str, text2: str) -> float:
    """
    Jaccard similarity between character 3-gram sets of two arbitrary strings.
    Returns: float in [0.0, 1.0]
    """
    grams1 = _extract_trigrams(text1)
    grams2 = _extract_trigrams(text2)

    if not grams1 or not grams2:
        return 0.0

    intersection = len(grams1 & grams2)
    union = len(grams1 | grams2)

    return intersection / union if union > 0 else 0.0


# ── Zero-Oracle Sequential Probe Detection ──────────────────────────────

def detect_probe_pattern(
    prompt: str,
    recent_prompts: Sequence[str],
    jaccard_threshold: float = 0.45,
) -> tuple[bool, float]:
    """
    Detect whether the incoming prompt is part of a side-channel probe sequence
    by comparing against the tenant's OWN recent prompt history.

    No target secret or length ceiling is used.

    Returns:
        (is_probe_attempt, similarity_score)
    """
    prompt_clean = prompt.strip()
    if not prompt_clean:
        return False, 0.0

    # 1. Cold-start short probe heuristic (e.g. 'O', 'OM', 'GET', etc.)
    if len(prompt_clean) <= 3:
        return True, 0.0

    # 2. Spaced-character mutation heuristic (e.g. 'O M E G A' or 'O M E G A _ 7 7')
    tokens = prompt_clean.split()
    if len(tokens) >= 3 and all(len(t) == 1 for t in tokens):
        return True, 0.75

    # 3. Check against tenant's recent prompt ring buffer
    max_similarity = 0.0
    for prev in recent_prompts:
        prev_clean = prev.strip()
        if not prev_clean or prev_clean == prompt_clean:
            continue

        # Pattern A: Incremental prefix extension (e.g. "O" -> "OM" -> "OME" -> "OMEG" -> "OMEGA")
        if prompt_clean.startswith(prev_clean) and 0 < len(prompt_clean) - len(prev_clean) <= 5:
            return True, 1.0
        if prev_clean.startswith(prompt_clean) and 0 < len(prev_clean) - len(prompt_clean) <= 5:
            return True, 1.0

        # Pattern B: Branching probe (testing candidates e.g. "OMEA" vs "OMEB")
        common_len = 0
        for c1, c2 in zip(prompt_clean, prev_clean):
            if c1 == c2:
                common_len += 1
            else:
                break
        if common_len >= 2 and abs(len(prompt_clean) - len(prev_clean)) <= 2:
            return True, 0.85

        # Pattern C: High 3-gram character Jaccard overlap (fuzzy mutation)
        score = compute_jaccard_3gram(prompt_clean, prev_clean)
        if score > max_similarity:
            max_similarity = score
        if score >= jaccard_threshold:
            return True, score

    return False, max_similarity


# ── Global Sybil / Multi-Tenant Rotation Probe Detection (Upgrade 1) ────

def detect_sybil_probe_pattern(
    tenant_id: str,
    prompt: str,
    global_window: Sequence[tuple[str, str]],
    jaccard_threshold: float = 0.45,
) -> tuple[bool, float]:
    """
    Detect cross-tenant sequential prefix probing across rotating Sybil tenant IDs.
    Compares the incoming prompt against GLOBAL_PROBE_WINDOW entries from DIFFERENT tenants.
    """
    prompt_clean = prompt.strip()
    if not prompt_clean or not global_window:
        return False, 0.0

    max_similarity = 0.0
    for prev_tid, prev_prompt in global_window:
        if prev_tid == tenant_id:
            continue  # Skip same tenant (already covered by per-tenant check)

        prev_clean = prev_prompt.strip()
        if not prev_clean:
            continue

        # Pattern A: Incremental prefix extension across tenants (e.g. sybil_1: "O" -> sybil_2: "OM")
        if prompt_clean.startswith(prev_clean) and 0 < len(prompt_clean) - len(prev_clean) <= 5:
            return True, 1.0
        if prev_clean.startswith(prompt_clean) and 0 < len(prev_clean) - len(prompt_clean) <= 5:
            return True, 1.0

        # Pattern B: Branching candidate probe (testing character options e.g. "OMEA" vs "OMEB")
        common_len = 0
        for c1, c2 in zip(prompt_clean, prev_clean):
            if c1 == c2:
                common_len += 1
            else:
                break
        min_len = min(len(prompt_clean), len(prev_clean))
        if common_len >= 2 and abs(len(prompt_clean) - len(prev_clean)) <= 2 and common_len >= min_len - 2:
            return True, 0.85

        # Pattern C: High 3-gram character Jaccard overlap (fuzzy mutation across tenants)
        score = compute_jaccard_3gram(prompt_clean, prev_clean)
        if score > max_similarity:
            max_similarity = score
        if score >= jaccard_threshold:
            return True, score

    return False, max_similarity


# ── vLLM PagedAttention 16-Token Block Alignment (Upgrade 4) ─────────────

def compute_vllm_block_alignment(prompt: str) -> str:
    """
    vLLM PagedAttention 16-Token Block Alignment Metadata.
    Accurately models how vLLM Automatic Prefix Caching (APC) allocates KV-cache
    in 16-token physical blocks and hashes block boundaries.
    Example: 'Block #4 (15 Padded + 1 Target Token)'
    """
    clean = prompt.strip()
    if not clean:
        return "Block #1 (15 Padded + 1 Target Token)"

    tokens = clean.split() if " " in clean else list(clean)
    token_count = max(1, len(tokens))
    block_num = ((token_count - 1) // 16) + 1
    rem = token_count % 16
    if rem == 0:
        rem = 16
    padded = 16 - rem
    return f"Block #{block_num} ({padded} Padded + 1 Target Token)"


# ── SPRT Log-Likelihood Update ──────────────────────────────────────────

def compute_sprt_update(
    adjusted_ttft_ms: float,
    prompt: str,
    recent_prompts: Sequence[str],
    config: GatewayConfig,
) -> tuple[float, bool, bool, float]:
    """
    Compute one step of Wald's SPRT using dynamic zero-oracle probe detection.

    Args:
        adjusted_ttft_ms: Observed TTFT after TCP jitter removal.
        prompt: Stripped user prompt.
        recent_prompts: Ring buffer of the tenant's recent prompts.
        config: Gateway configuration.

    Returns:
        (llr_delta, is_probe_attempt, is_timing_signal, similarity_score)
    """
    is_probe_attempt, similarity_score = detect_probe_pattern(
        prompt, recent_prompts, config.jaccard_threshold
    )

    if not is_probe_attempt:
        # Benign enterprise traffic — SPRT does not increment
        return 0.0, False, False, similarity_score

    # Timing signal: Cache hit = fast TTFT below threshold
    is_timing_signal = adjusted_ttft_ms < config.ttft_threshold_ms

    p0 = config.sprt_p0
    p1 = config.sprt_p1

    if is_timing_signal:
        # Evidence FOR attacker: log(p1/p0) ≈ +2.0794
        llr_delta = math.log(p1 / p0)
    else:
        # Evidence AGAINST attacker: log((1-p1)/(1-p0)) ≈ -0.4615
        llr_delta = math.log((1 - p1) / (1 - p0))

    return llr_delta, is_probe_attempt, is_timing_signal, similarity_score


def compute_sybil_sprt_update(
    adjusted_ttft_ms: float,
    tenant_id: str,
    prompt: str,
    global_window: Sequence[tuple[str, str]],
    config: GatewayConfig,
) -> tuple[float, bool, bool, float]:
    """
    SPRT update for Global Sybil Prefix Anomaly Shield.
    Returns:
        (sybil_llr_delta, is_sybil_attempt, is_timing_signal, similarity_score)
    """
    is_sybil_attempt, similarity_score = detect_sybil_probe_pattern(
        tenant_id, prompt, global_window, config.jaccard_threshold
    )

    if not is_sybil_attempt:
        return 0.0, False, False, similarity_score

    is_timing_signal = adjusted_ttft_ms < config.ttft_threshold_ms
    p0 = config.sprt_p0
    p1 = config.sprt_p1

    if is_timing_signal:
        llr_delta = math.log(p1 / p0)
    else:
        llr_delta = math.log((1 - p1) / (1 - p0))

    return llr_delta, is_sybil_attempt, is_timing_signal, similarity_score
