"""
Aegis-KV Gateway Configuration.

Global settings for SPRT thresholds, timing profiles, defense params,
and the demo secret. Single dataclass, no external config files.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class GatewayConfig:
    """All tunable knobs for the Aegis-KV gateway."""

    # ── SPRT Thresholds (Wald's Sequential Probability Ratio Test) ───────
    sprt_alpha: float = 0.01       # False positive rate (Type I error)
    sprt_beta: float = 0.01        # False negative rate (Type II error)
    sprt_p0: float = 0.05          # Null: 5% probe rate (normal noise)
    sprt_p1: float = 0.40          # Alt: 40% probe rate (attacker)

    # ── Timing Profiles ──────────────────────────────────────────────────
    timing_profile: str = "70B_vLLM"       # "70B_vLLM" | "0.5B_Edge"
    ttft_cache_hit_ms: float = 12.0        # Expected TTFT on cache hit (70B)
    ttft_cache_miss_ms: float = 85.0       # Expected TTFT on cache miss (70B)
    ttft_threshold_ms: float = 30.0        # Below this = likely cache hit

    # ── Defense Parameters ───────────────────────────────────────────────
    padding_bucket_ms: float = 85.0        # Constant-time ceiling matching cache-miss ceiling (85ms)
    tcp_jitter_estimate_ms: float = 3.0    # L4 jitter to subtract
    defense_enabled: bool = True           # Master switch
    max_in_flight_burst: int = 3           # Concurrency limit before TOCTOU ceiling padding

    # ── Time Decay & Cooldown TTL (Production Upgrades) ──────────────────
    quarantine_ttl_sec: float = 30.0       # Auto-unquarantine TTL cooldown window
    llr_decay_rate: float = 0.05           # Exponential LLR decay rate for benign idle time

    # ── Shingling ────────────────────────────────────────────────────────
    jaccard_threshold: float = 0.45        # Fuzzy match threshold (0.45 catches space-mutations)

    # ── Demo Secret ──────────────────────────────────────────────────────
    hidden_secret: str = "OMEGA_77"        # System prompt the red team steals (used in simulated LLM)

    # ── Derived Wald Boundaries (computed, not user-set) ─────────────────
    @property
    def sprt_upper_boundary(self) -> float:
        """Threshold A: reject null (declare attacker). LLR >= A."""
        return math.log((1 - self.sprt_beta) / self.sprt_alpha)

    @property
    def sprt_lower_boundary(self) -> float:
        """Threshold B: accept null (declare benign). LLR <= B."""
        return math.log(self.sprt_beta / (1 - self.sprt_alpha))

    def apply_timing_profile(self, profile: str) -> None:
        """Switch between 70B_vLLM and 0.5B_Edge timing profiles."""
        self.timing_profile = profile
        if profile == "0.5B_Edge":
            self.ttft_cache_hit_ms = 3.0
            self.ttft_cache_miss_ms = 18.0
            self.ttft_threshold_ms = 8.0
            self.padding_bucket_ms = 20.0
        else:  # Default: 70B_vLLM
            self.ttft_cache_hit_ms = 12.0
            self.ttft_cache_miss_ms = 85.0
            self.ttft_threshold_ms = 30.0
            self.padding_bucket_ms = 85.0


# ── Global Singleton ─────────────────────────────────────────────────────
GATEWAY_CONFIG = GatewayConfig()
