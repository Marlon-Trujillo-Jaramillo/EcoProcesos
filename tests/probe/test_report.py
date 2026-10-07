from __future__ import annotations

from ecoprocesos.probe.capabilities import SourceState, SourceStatus
from ecoprocesos.probe.cost import ScanCost
from ecoprocesos.probe.report import SCHEMA_VERSION, build_report, parse_os_release, render_summary


def test_parse_os_release_strips_quotes_and_ignores_comments():
    text = '# comment\nNAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n\nBROKEN_LINE\n'

    assert parse_os_release(text) == {"NAME": "Ubuntu", "VERSION_ID": "24.04", "ID": "ubuntu"}


def _sample_report():
    statuses = [
        SourceStatus("psi", SourceState.OK, "cpu, memory, io"),
        SourceStatus("journald", SourceState.DEGRADED, "not in systemd-journal group"),
        SourceStatus("tts_piper", SourceState.DISABLED, "piper not installed"),
    ]
    costs = [ScanCost("raw_proc", 20, 312, 6.0, 9.0, 8.0)]
    return build_report(statuses, costs, host={"distro": "Ubuntu 24.04"})


def test_build_report_has_versioned_schema_and_state_totals():
    report = _sample_report()

    assert report["schema_version"] == SCHEMA_VERSION
    assert report["totals"] == {"ok": 1, "degraded": 1, "disabled": 1}
    assert report["sources"][1]["state"] == "degraded"
    assert report["cost"][0]["processes"] == 312


def test_render_summary_mentions_every_source_and_cost():
    summary = render_summary(_sample_report())

    for name in ("psi", "journald", "tts_piper", "raw_proc"):
        assert name in summary
