"""
Aegis-KV — Telemetry Ring Buffer + SSE Event Emitter.

Stores recent TelemetryEvents in an in-memory ring buffer, and broadcasts
live events to connected SSE (Server-Sent Events) clients in real-time.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from time import time


@dataclass
class TelemetryEvent:
    """Single event in the telemetry stream."""

    timestamp: float = field(default_factory=time)
    tenant_id: str = ""
    event_type: str = ""             # "probe_detected" | "probe_miss" | "benign" | "quarantine"
    ttft_raw_ms: float = 0.0         # Observed TTFT from mock LLM
    ttft_adjusted_ms: float = 0.0    # After L4 jitter removal
    ttft_padded_ms: float = 0.0      # Effective TTFT (with defense padding if quarantined)
    padding_ms: float = 0.0          # Delay added by bucket padding
    llr_before: float = 0.0          # LLR before this event
    llr_after: float = 0.0           # LLR after this event
    llr_delta: float = 0.0           # Change applied
    cache_salt: str = "default"
    hot_path_overhead_ms: float = 0.0
    shingling_score: float = 0.0     # Jaccard similarity [0.0, 1.0]
    prompt_snippet: str = ""         # First 40 chars for log display
    is_probe_attempt: bool = False
    is_timing_signal: bool = False
    is_cache_hit: bool = False
    blocked: bool = False            # True if defense padded/quarantined
    vllm_block_alignment: str = ""   # e.g. "Block #4 (15 Padded + 1 Target Token)"
    quarantine_ttl_remaining_s: float = 0.0  # Remaining quarantine cooldown TTL
    global_sybil_llr: float = 0.0    # Cross-tenant Sybil shield LLR

    def to_dict(self) -> dict:
        """Serialize for JSON/SSE transport."""
        return {
            "timestamp": round(self.timestamp, 3),
            "tenant_id": self.tenant_id,
            "event_type": self.event_type,
            "ttft_raw_ms": round(self.ttft_raw_ms, 2),
            "ttft_adjusted_ms": round(self.ttft_adjusted_ms, 2),
            "ttft_padded_ms": round(self.ttft_padded_ms, 2),
            "padding_ms": round(self.padding_ms, 2),
            "llr_before": round(self.llr_before, 4),
            "llr_after": round(self.llr_after, 4),
            "llr_delta": round(self.llr_delta, 4),
            "cache_salt": self.cache_salt,
            "hot_path_overhead_ms": round(self.hot_path_overhead_ms, 4),
            "shingling_score": round(self.shingling_score, 4),
            "prompt_snippet": self.prompt_snippet,
            "is_probe_attempt": self.is_probe_attempt,
            "is_timing_signal": self.is_timing_signal,
            "is_cache_hit": self.is_cache_hit,
            "blocked": self.blocked,
            "vllm_block_alignment": self.vllm_block_alignment,
            "quarantine_ttl_remaining_s": round(self.quarantine_ttl_remaining_s, 1),
            "global_sybil_llr": round(self.global_sybil_llr, 4),
        }


@dataclass
class TelemetryLog:
    """Fixed-size ring buffer + SSE subscriber broadcaster."""

    events: list[TelemetryEvent] = field(default_factory=list)
    max_events: int = 500
    subscribers: list[asyncio.Queue] = field(default_factory=list)

    def subscribe(self) -> asyncio.Queue:
        """Register a new SSE client subscriber queue."""
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self.subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        """Unregister an SSE client subscriber queue."""
        if q in self.subscribers:
            self.subscribers.remove(q)

    def push(self, event: TelemetryEvent) -> None:
        """Append event to ring buffer and broadcast to all active SSE subscribers."""
        self.events.append(event)
        if len(self.events) > self.max_events:
            self.events.pop(0)

        event_data = event.to_dict()
        # Broadcast to active queues
        for q in list(self.subscribers):
            try:
                q.put_nowait(event_data)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                    q.put_nowait(event_data)
                except Exception:
                    pass
            except Exception:
                pass

    def recent(self, n: int = 50) -> list[dict]:
        """Return last N events as dicts (for API/SSE initial sync)."""
        return [e.to_dict() for e in self.events[-n:]]

    def clear(self) -> None:
        """Wipe all events (for demo reset)."""
        self.events.clear()


# ── Global Singleton ─────────────────────────────────────────────────────
TELEMETRY = TelemetryLog()
