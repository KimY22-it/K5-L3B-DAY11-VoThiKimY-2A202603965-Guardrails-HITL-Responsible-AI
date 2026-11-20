"""
Assignment 11 — Monitoring & Alerts starter (TODO).

Tracks block rate, rate-limit hits, judge fail rate.
Fires alerts when thresholds are exceeded.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


def default_metrics_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "metrics.json")


@dataclass
class Alert:
    metric: str
    value: float
    threshold: float
    message: str


@dataclass
class MonitoringAlert:
    """Aggregate counters from pipeline plugins and emit alerts."""

    block_rate_threshold: float = 0.5
    rate_limit_hit_threshold: int = 5
    judge_fail_rate_threshold: float = 0.3
    alerts: list[Alert] = field(default_factory=list)

    # Counters — update these from your pipeline after each request
    total_requests: int = 0
    blocked_requests: int = 0
    rate_limit_hits: int = 0
    judge_checks: int = 0
    judge_fails: int = 0

    def check_metrics(self) -> list[Alert]:
        """TODO: compute rates, append Alert objects when thresholds exceeded."""
        metrics = self._metrics()
        triggered = []
        for metric, threshold in (
            ("block_rate", self.block_rate_threshold),
            ("rate_limit_hits", self.rate_limit_hit_threshold),
            ("judge_fail_rate", self.judge_fail_rate_threshold),
        ):
            value = metrics[metric]
            if value > threshold:
                triggered.append(Alert(
                    metric=metric,
                    value=value,
                    threshold=threshold,
                    message=f"{metric} ({value:.4g}) exceeded its threshold ({threshold:.4g}).",
                ))

        self.alerts.extend(triggered)
        return triggered

    def export_json(self, filepath: str | None = None):
        """TODO: write metrics + alerts to JSON under repo-root ``outputs/`` by default.
        Use ``filepath or default_metrics_path()`` so running from ``src/`` does not
        create ``src/outputs/``.
        """
        path = Path(filepath or default_metrics_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as stream:
            json.dump(self.snapshot(), stream, indent=2)

    def _metrics(self) -> dict[str, int | float]:
        block_rate = (
            self.blocked_requests / self.total_requests
            if self.total_requests
            else 0.0
        )
        judge_fail_rate = (
            self.judge_fails / self.judge_checks if self.judge_checks else 0.0
        )
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": block_rate,
            "rate_limit_hits": self.rate_limit_hits,
            "judge_checks": self.judge_checks,
            "judge_fails": self.judge_fails,
            "judge_fail_rate": judge_fail_rate,
        }

    def snapshot(self) -> dict:
        return {
            **self._metrics(),
            "alerts": [
                {
                    "metric": a.metric,
                    "value": a.value,
                    "threshold": a.threshold,
                    "message": a.message,
                }
                for a in self.alerts
            ],
        }
