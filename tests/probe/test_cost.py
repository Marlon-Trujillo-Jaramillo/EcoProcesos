from __future__ import annotations

import itertools

import pytest

from ecoprocesos.probe.cost import ScanCost, measure, percentile, scan_once


class TestScanOnce:
    def test_reads_every_visible_process(self, fake_proc):
        fake_proc.add_process(1, uid=0)
        fake_proc.add_process(2)
        fake_proc.add_psi("cpu")

        assert scan_once(fake_proc.root) == 2

    def test_skips_processes_that_vanish_mid_scan(self, fake_proc):
        fake_proc.add_process(1)
        gone = fake_proc.add_process(2)
        (gone / "cgroup").unlink()

        assert scan_once(fake_proc.root) == 1


class TestPercentile:
    @pytest.mark.parametrize(
        "values, q, expected",
        [([5.0], 0.95, 5.0), ([1.0, 2.0, 3.0, 4.0], 0.5, 2.5), ([1.0, 2.0, 3.0, 4.0, 5.0], 1.0, 5.0)],
    )
    def test_linear_interpolation(self, values, q, expected):
        assert percentile(values, q) == pytest.approx(expected)

    def test_rejects_empty_input(self):
        with pytest.raises(ValueError):
            percentile([], 0.5)


class TestMeasure:
    def test_aggregates_cpu_and_wall_time_per_iteration(self):
        cpu = itertools.count(start=0.0, step=0.004)  # 4 ms CPU per scan
        wall = itertools.count(start=0.0, step=0.010)  # 10 ms wall per scan

        cost = measure(
            lambda: 300,
            iterations=5,
            method="raw_proc",
            cpu_clock=lambda: next(cpu),
            wall_clock=lambda: next(wall),
        )

        assert cost.processes == 300
        assert cost.cpu_ms_mean == pytest.approx(4.0)
        assert cost.wall_ms_mean == pytest.approx(10.0)

    def test_rejects_non_positive_iterations(self):
        with pytest.raises(ValueError):
            measure(lambda: 1, iterations=0, method="raw_proc")


class TestScanCost:
    def test_core_percent_at_interval(self):
        cost = ScanCost(method="raw_proc", iterations=10, processes=300, cpu_ms_mean=6.0, cpu_ms_p95=8.0, wall_ms_mean=9.0)

        # 6 ms of CPU every 3 s -> 0.2 % of one core
        assert cost.core_percent(3.0) == pytest.approx(0.2)

    def test_serializes_projected_load_for_candidate_intervals(self):
        cost = ScanCost(method="raw_proc", iterations=10, processes=300, cpu_ms_mean=10.0, cpu_ms_p95=12.0, wall_ms_mean=15.0)

        data = cost.to_dict()

        assert data["core_percent_by_interval_s"]["2"] == pytest.approx(0.5)
        assert set(data["core_percent_by_interval_s"]) == {"2", "3", "5", "8"}


class TestMeasurePacing:
    def test_warms_up_and_pauses_between_iterations(self):
        calls = []
        pauses = []

        measure(lambda: calls.append(1) or 1, iterations=3, method="raw_proc", pause=pauses.append, pause_s=0.1)

        assert len(calls) == 4  # one warm-up scan plus three measured
        assert pauses == [0.1, 0.1, 0.1]
