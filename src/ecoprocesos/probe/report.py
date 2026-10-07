"""Assembles the Phase 0 feasibility report (JSON for analysis, text for humans)."""

from __future__ import annotations

import datetime as dt
import os
import platform
from collections import Counter
from pathlib import Path
from typing import Dict, Mapping, Optional, Sequence

from ecoprocesos.probe.capabilities import SourceState, SourceStatus
from ecoprocesos.probe.cost import ScanCost

SCHEMA_VERSION = 1


def parse_os_release(text: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key] = value.strip().strip('"').strip("'")
    return result


def host_info(etc_root: Path = Path("/etc"), environ: Optional[Mapping[str, str]] = None) -> Dict[str, object]:
    environ = os.environ if environ is None else environ
    try:
        os_release = parse_os_release((etc_root / "os-release").read_text())
    except OSError:
        os_release = {}
    return {
        "distro": os_release.get("PRETTY_NAME", platform.system()),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "desktop": environ.get("XDG_CURRENT_DESKTOP", ""),
        "session_type": environ.get("XDG_SESSION_TYPE", ""),
        "cpu_count": os.cpu_count(),
        "euid": os.geteuid(),
        "python": platform.python_version(),
    }


def build_report(
    statuses: Sequence[SourceStatus], costs: Sequence[ScanCost], host: Mapping[str, object]
) -> Dict[str, object]:
    counts = Counter(s.state for s in statuses)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "host": dict(host),
        "totals": {state.value: counts.get(state, 0) for state in SourceState},
        "sources": [s.to_dict() for s in statuses],
        "cost": [c.to_dict() for c in costs],
    }


_MARK = {"ok": "OK  ", "degraded": "DEGR", "disabled": "OFF "}


def render_summary(report: Mapping[str, object]) -> str:
    host = report["host"]
    lines = [f"EcoProcesos probe - {host.get('distro', '?')} ({host.get('desktop') or 'no desktop'})", ""]
    for source in report["sources"]:
        lines.append(f"  [{_MARK[source['state']]}] {source['source']:<22} {source['detail']}")
    lines.append("")
    for cost in report["cost"]:
        per_interval = ", ".join(f"{i}s={p:.2f}%" for i, p in cost["core_percent_by_interval_s"].items())
        lines.append(
            f"  {cost['method']:<10} {cost['processes']} procs, CPU {cost['cpu_ms_mean']:.2f} ms/scan "
            f"(p95 {cost['cpu_ms_p95']:.2f}) -> core load {per_interval}"
        )
    totals = report["totals"]
    lines.append("")
    lines.append(f"  totals: {totals['ok']} ok, {totals['degraded']} degraded, {totals['disabled']} disabled")
    return "\n".join(lines)
