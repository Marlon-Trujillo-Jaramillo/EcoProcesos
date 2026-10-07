"""Measures what a full /proc scan costs, to fix the CPU budget with real data."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

# Files the MVP collector reads for every process on each tick.
PER_PROCESS_FILES = ("stat", "cmdline", "cgroup")
CANDIDATE_INTERVALS_S = (2, 3, 5, 8)


def scan_once(proc_root: Path) -> int:
    """Read the per-process files the collector needs; return how many processes were read."""
    count = 0
    for entry in os.scandir(proc_root):
        if not entry.name.isdigit():
            continue
        try:
            for name in PER_PROCESS_FILES:
                with open(os.path.join(entry.path, name), "rb") as fh:
                    data = fh.read()
                if name == "stat":
                    # Parse like the collector will: fields after the "(comm)" which may contain spaces.
                    data[data.rfind(b")") + 2 :].split()
        except OSError:  # process exited mid-scan or is hidden
            continue
        count += 1
    return count


def psutil_scan() -> Optional[Callable[[], int]]:
    """A psutil scan reading what the MVP collector needs (it also reads status/statm,
    so it is the more realistic cost figure), or None if psutil is missing."""
    try:
        import psutil
    except ImportError:
        return None
    attrs = ["pid", "ppid", "name", "status", "cpu_times", "memory_info", "num_threads", "cmdline"]

    def scan() -> int:
        return sum(1 for _ in psutil.process_iter(attrs))

    return scan


def percentile(values: Sequence[float], q: float) -> float:
    if not values:
        raise ValueError("percentile of empty sequence")
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    low = int(pos)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (pos - low)


@dataclass(frozen=True)
class ScanCost:
    method: str
    iterations: int
    processes: int
    cpu_ms_mean: float
    cpu_ms_p95: float
    wall_ms_mean: float

    def core_percent(self, interval_s: float) -> float:
        """Share of one core spent scanning if a scan runs every interval_s seconds."""
        return self.cpu_ms_mean / (interval_s * 1000) * 100

    def to_dict(self) -> Dict[str, object]:
        return {
            "method": self.method,
            "iterations": self.iterations,
            "processes": self.processes,
            "cpu_ms_mean": round(self.cpu_ms_mean, 3),
            "cpu_ms_p95": round(self.cpu_ms_p95, 3),
            "wall_ms_mean": round(self.wall_ms_mean, 3),
            "core_percent_by_interval_s": {str(i): round(self.core_percent(i), 4) for i in CANDIDATE_INTERVALS_S},
        }


def measure(
    scan: Callable[[], int],
    iterations: int,
    method: str,
    cpu_clock: Callable[[], float] = time.process_time,
    wall_clock: Callable[[], float] = time.perf_counter,
    pause: Callable[[float], None] = time.sleep,
    pause_s: float = 0.0,
) -> ScanCost:
    """Warm up once, then time each scan, pausing between scans like a real polling loop."""
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    cpu_ms: List[float] = []
    wall_ms: List[float] = []
    processes = scan()
    for _ in range(iterations):
        pause(pause_s)
        cpu_start, wall_start = cpu_clock(), wall_clock()
        processes = scan()
        cpu_ms.append((cpu_clock() - cpu_start) * 1000)
        wall_ms.append((wall_clock() - wall_start) * 1000)
    return ScanCost(
        method=method,
        iterations=iterations,
        processes=processes,
        cpu_ms_mean=sum(cpu_ms) / iterations,
        cpu_ms_p95=percentile(cpu_ms, 0.95),
        wall_ms_mean=sum(wall_ms) / iterations,
    )
