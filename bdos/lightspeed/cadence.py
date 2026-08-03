"""Cadence analysis.

Distinguishes human cadence from machine cadence using the timing of recent
actions. Two signals matter: *volume* (how many actions in the window, relative
to a plausible human rate) and *regularity* (machines fire at metronomic
intervals; humans do not). The output is a dimensionless ``burst_score`` that
the throttle turns into delay.
"""

from __future__ import annotations

from typing import Sequence

from bdos.core.config import LightspeedConfig


def burst_score(arrivals: Sequence[float], now: float, cfg: LightspeedConfig) -> float:
    """Return a non-negative burst score for a principal's recent cadence.

    ``0.0`` means "at or below human cadence" (no penalty). The score grows as
    the action rate exceeds a plausible human rate, and is amplified when the
    cadence is fast *and* metronomically regular -- the signature of a script.

    ``arrivals`` are monotonic timestamps (seconds); only those within
    ``cfg.window_seconds`` of ``now`` are considered.
    """
    window = [t for t in arrivals if now - t <= cfg.window_seconds]
    n = len(window)
    if n <= 1:
        return 0.0

    # Volume pressure: how far above a plausible human count we are.
    expected_human = max(1.0, cfg.window_seconds / max(cfg.human_cadence_threshold, 1e-9))
    volume_pressure = max(0.0, n / expected_human - 1.0)
    if volume_pressure == 0.0:
        return 0.0

    # Regularity amplifier: fast + regular cadence looks scripted.
    window = sorted(window)
    iats = [window[i] - window[i - 1] for i in range(1, n)]
    mean_iat = sum(iats) / len(iats)
    amp = 1.0
    if mean_iat < cfg.human_cadence_threshold and len(iats) >= 2:
        var = sum((x - mean_iat) ** 2 for x in iats) / len(iats)
        std = var ** 0.5
        cv = (std / mean_iat) if mean_iat > 0 else 0.0
        regularity = max(0.0, 1.0 - min(1.0, cv))  # 1.0 == perfectly regular
        speed = (cfg.human_cadence_threshold - mean_iat) / cfg.human_cadence_threshold
        amp = 1.0 + regularity * speed  # up to 2x for fast, metronomic bursts

    return volume_pressure * amp


def looks_agentic(arrivals: Sequence[float], now: float, cfg: LightspeedConfig) -> bool:
    """Heuristic reclassification: does this cadence look like a machine?

    Used to catch a principal that *claims* to be human but behaves like a
    script. A single humanlike burst won't trip it; sustained super-human
    cadence will.
    """
    return burst_score(arrivals, now, cfg) >= 1.0
