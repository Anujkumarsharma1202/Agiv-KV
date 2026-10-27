"""
Aegis-KV In-Memory Tenant State Store.

O(1) dict-based lookup — no Redis, no database.
Each tenant gets an isolated TenantState tracking SPRT, timing, and quarantine.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from time import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gateway.config import GatewayConfig


@dataclass
class TenantState:
    """Per-tenant security state (lives in-process memory)."""

    tenant_id: str

    # ── SPRT Engine ──────────────────────────────────────────────────────
    llr: float = 0.0                   # Log-Likelihood Ratio (running sum)
    request_count: int = 0             # Total requests from this tenant
    probe_count: int = 0               # Requests flagged as probing
    is_quarantined: bool = False       # True = cache_salt isolated

    # ── Cache Salt & Quarantine TTL (Upgrade 3) ──────────────────────────
    cache_salt: str = "default"        # Rotated on quarantine
    quarantined_until: float = 0.0     # Epoch timestamp when quarantine expires

    # ── TOCTOU In-Flight Concurrency Guard (Upgrade 2) ────────────────────
    in_flight: int = 0                 # Active concurrent requests in flight

    # ── Timing History (sliding window) ──────────────────────────────────
    ttft_history: list[float] = field(default_factory=list)
    max_history: int = 50

    # ── Prompt History for Sequential Probe Detection ────────────────────
    recent_prompts: deque[str] = field(default_factory=lambda: deque(maxlen=10))

    # ── Shingling ────────────────────────────────────────────────────────
    seen_trigrams: set[str] = field(default_factory=set)

    # ── Timestamps & Exponential Decay (Upgrade 3) ───────────────────────
    first_seen: float = field(default_factory=time)
    last_seen: float = field(default_factory=time)
    last_request_ts: float = field(default_factory=time)

    @property
    def quarantine_ttl_remaining(self) -> float:
        """Remaining quarantine TTL in seconds (0.0 if not quarantined)."""
        if not self.is_quarantined or self.quarantined_until <= 0.0:
            return 0.0
        return max(0.0, round(self.quarantined_until - time(), 1))

    def check_cooldown_and_decay(self, config: GatewayConfig, now: float | None = None) -> None:
        """
        1. Auto-unquarantine if cooldown TTL expired.
        2. Apply gentle exponential time-decay to LLR if idle > 2.0s.
        """
        if now is None:
            now = time()

        # Auto-cooldown check: Unquarantine if TTL elapsed
        if self.is_quarantined and self.quarantined_until > 0.0 and now >= self.quarantined_until:
            self.is_quarantined = False
            self.quarantined_until = 0.0
            self.cache_salt = "default"
            self.llr = 0.0

        # Exponential time-decay on LLR during benign idle gaps (> 2.0s)
        idle_time = now - self.last_request_ts
        if idle_time > 2.0 and not self.is_quarantined:
            self.llr = max(0.0, self.llr * math.exp(-config.llr_decay_rate * idle_time))

        self.last_request_ts = now

    def record_ttft(self, ttft_ms: float) -> None:
        """Append TTFT to sliding window, evicting oldest if full."""
        self.ttft_history.append(ttft_ms)
        if len(self.ttft_history) > self.max_history:
            self.ttft_history.pop(0)
        self.last_seen = time()

    def record_prompt(self, prompt: str) -> None:
        """Store prompt in sliding ring buffer for sequential probe analysis."""
        self.recent_prompts.append(prompt)

    def reset(self) -> None:
        """Reset detection state (for demo resets)."""
        self.llr = 0.0
        self.request_count = 0
        self.probe_count = 0
        self.is_quarantined = False
        self.quarantined_until = 0.0
        self.in_flight = 0
        self.cache_salt = "default"
        self.ttft_history.clear()
        self.recent_prompts.clear()
        self.seen_trigrams.clear()
        self.last_request_ts = time()


# ── Global In-Memory Store ───────────────────────────────────────────────
TENANTS: dict[str, TenantState] = {}

# ── Global Sybil Shield: Multi-Tenant Rotation Detection (Upgrade 1) ─────
GLOBAL_PROBE_WINDOW: deque[tuple[str, str]] = deque(maxlen=25)  # (tenant_id, prompt)
GLOBAL_SYBIL_LLR: float = 0.0


def get_global_sybil_llr() -> float:
    """Read current Global Sybil Log-Likelihood Ratio."""
    global GLOBAL_SYBIL_LLR
    return GLOBAL_SYBIL_LLR


def set_global_sybil_llr(val: float) -> None:
    """Set Global Sybil LLR with non-negative floor."""
    global GLOBAL_SYBIL_LLR
    GLOBAL_SYBIL_LLR = max(0.0, val)


def update_global_sybil_llr(delta: float) -> float:
    """Update Global Sybil LLR by delta, floored at 0.0."""
    global GLOBAL_SYBIL_LLR
    GLOBAL_SYBIL_LLR = max(0.0, GLOBAL_SYBIL_LLR + delta)
    return GLOBAL_SYBIL_LLR


def record_global_probe(tenant_id: str, prompt: str) -> None:
    """Append probe to the global cross-tenant ring buffer."""
    GLOBAL_PROBE_WINDOW.append((tenant_id, prompt))


def get_or_create_tenant(tenant_id: str) -> TenantState:
    """O(1) dict lookup. Creates TenantState on first encounter."""
    tenant = TENANTS.get(tenant_id)
    if tenant is None:
        tenant = TenantState(tenant_id=tenant_id)
        TENANTS[tenant_id] = tenant
    return tenant


def reset_all_tenants() -> None:
    """Wipe all tenant state and global Sybil anomaly tracker (for demo resets)."""
    global GLOBAL_SYBIL_LLR
    TENANTS.clear()
    GLOBAL_PROBE_WINDOW.clear()
    GLOBAL_SYBIL_LLR = 0.0
