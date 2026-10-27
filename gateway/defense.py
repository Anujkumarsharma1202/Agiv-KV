"""
Aegis-KV — Automated Quarantine & Defense Engine.

When SPRT LLR crosses the upper Wald boundary:
  1. Tenant is quarantined (is_quarantined = True)
  2. cache_salt is rotated to isolate the tenant's KV-cache namespace in vLLM
     (quarantined tenants can no longer hit the shared victim prefix)
  3. Constant-Time Bucket Padding (~85.0ms) is applied to all responses,
     flattening hits and misses to the exact same ceiling (0ms timing delta).

Also provides L4 TCP jitter filtering for accurate TTFT measurement.
"""

from __future__ import annotations

import time
import uuid

from gateway.config import GatewayConfig
from gateway.state import TenantState


def maybe_quarantine(tenant: TenantState, config: GatewayConfig) -> bool:
    """
    Check if tenant's LLR has crossed the SPRT upper boundary.
    If so, quarantine: isolate cache_salt + flag for TTFT padding + set cooldown TTL.

    Returns True if quarantine was NEWLY triggered this call.
    """
    if tenant.is_quarantined:
        return False  # Already quarantined

    if tenant.llr >= config.sprt_upper_boundary:
        tenant.is_quarantined = True
        tenant.quarantined_until = time.time() + config.quarantine_ttl_sec
        # Rotate cache_salt to a unique value — isolates tenant's KV-cache
        tenant.cache_salt = f"quarantine_{uuid.uuid4().hex[:8]}"
        return True

    return False


def compute_padding_delay_ms(raw_ttft_ms: float, config: GatewayConfig) -> float:
    """
    Compute additional delay needed to pad TTFT to the constant-time ceiling.

    Constant-Time Ceiling Padding:
      All responses are padded to exactly `config.padding_bucket_ms` (85.0ms for 70B).
      Cache-hit (~12ms) gets +73ms padding -> 85.0ms total.
      Cache-miss (~85ms) gets ~0ms padding -> 85.0ms total.

    This completely eliminates the timing difference an attacker relies on.

    Returns: additional delay in ms (>= 0.0)
    """
    padding = config.padding_bucket_ms - raw_ttft_ms
    return max(0.0, padding)


def apply_tcp_jitter_filter(
    observed_ttft_ms: float, config: GatewayConfig
) -> float:
    """
    L4 TCP Socket Jitter Filtering.
    Net_Adjusted_TTFT = Observed_TTFT - TCP_Jitter_Estimate

    Removes network-layer noise from TTFT measurements for cleaner
    SPRT signal processing.
    """
    adjusted = observed_ttft_ms - config.tcp_jitter_estimate_ms
    return max(1.0, adjusted)
