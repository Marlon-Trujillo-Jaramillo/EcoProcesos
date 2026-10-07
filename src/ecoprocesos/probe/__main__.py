"""CLI: python -m ecoprocesos.probe [--out report.json]"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from ecoprocesos.probe.capabilities import ProbeEnv, run_all
from ecoprocesos.probe.cost import ScanCost, measure, psutil_scan, scan_once
from ecoprocesos.probe.report import build_report, host_info, render_summary


# Pause between measured scans so caches cool down like in a real polling loop.
SCAN_PAUSE_S = 0.1


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _measure_costs(env: ProbeEnv, iterations: int) -> List[ScanCost]:
    costs = [measure(lambda: scan_once(env.proc_root), iterations, "raw_proc", pause_s=SCAN_PAUSE_S)]
    scan = psutil_scan()
    if scan is not None:
        costs.append(measure(scan, iterations, "psutil", pause_s=SCAN_PAUSE_S))
    return costs


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="ecoprocesos.probe", description="Phase 0 feasibility probe")
    parser.add_argument("--out", type=Path, default=Path("probe-report.json"), help="JSON report path")
    parser.add_argument("--iterations", type=_positive_int, default=30, help="scans per cost measurement")
    parser.add_argument("--skip-cost", action="store_true", help="only probe capabilities")
    args = parser.parse_args(argv)

    if not sys.platform.startswith("linux"):
        print(f"warning: running on {sys.platform}; results are only meaningful on Linux", file=sys.stderr)

    env = ProbeEnv()
    statuses = run_all(env)

    costs: List[ScanCost] = []
    if not args.skip_cost and env.proc_root.is_dir():
        try:
            costs = _measure_costs(env, args.iterations)
        except Exception as exc:  # noqa: BLE001 - keep the capability results even if measuring fails
            print(f"warning: cost measurement failed: {type(exc).__name__}: {exc}", file=sys.stderr)

    report = build_report(statuses, costs, host_info())
    print(render_summary(report))
    try:
        args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"\nerror: could not write {args.out}: {exc}", file=sys.stderr)
        return 1
    print(f"\nreport written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
