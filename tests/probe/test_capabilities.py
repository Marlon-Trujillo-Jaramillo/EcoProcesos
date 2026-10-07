from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Optional, Sequence

import pytest

from ecoprocesos.probe.capabilities import (
    CommandResult,
    ProbeEnv,
    SourceState,
    probe_cgroup_app_scopes,
    probe_desktop_entries,
    probe_foreign_exe,
    probe_foreign_io,
    probe_foreign_smaps,
    probe_hidepid,
    probe_journald,
    probe_meminfo,
    probe_proc_listing,
    probe_psi,
    probe_tts_piper,
    run_all,
)

OWN_UID = 1000


def make_env(
    proc_root: Path,
    *,
    tmp_path: Optional[Path] = None,
    binaries: Optional[Dict[str, str]] = None,
    commands: Optional[Dict[str, CommandResult]] = None,
    desktop_dirs: Sequence[Path] = (),
) -> ProbeEnv:
    binaries = binaries or {}
    commands = commands or {}

    def which(name: str) -> Optional[str]:
        return binaries.get(name)

    def run(argv: Sequence[str], timeout_s: float) -> CommandResult:
        return commands.get(Path(argv[0]).name, CommandResult(127, "", "not found", 0.0))

    return ProbeEnv(
        proc_root=proc_root,
        sys_root=(tmp_path or proc_root.parent) / "sys",
        desktop_dirs=tuple(desktop_dirs),
        euid=OWN_UID,
        which=which,
        run=run,
    )


class TestProcListing:
    def test_counts_numeric_entries_only(self, fake_proc):
        fake_proc.add_process(1, uid=0)
        fake_proc.add_process(42)
        fake_proc.add_psi("cpu")

        status = probe_proc_listing(make_env(fake_proc.root))

        assert status.state is SourceState.OK
        assert status.data["visible_processes"] == 2

    def test_disabled_when_proc_root_missing(self, tmp_path):
        status = probe_proc_listing(make_env(tmp_path / "nope"))

        assert status.state is SourceState.DISABLED


class TestHidepid:
    def test_ok_without_hidepid_option(self, fake_proc):
        fake_proc.add_mounts()

        assert probe_hidepid(make_env(fake_proc.root)).state is SourceState.OK

    def test_ok_when_hidepid_is_explicitly_off(self, fake_proc):
        fake_proc.add_mounts("rw,hidepid=0")

        assert probe_hidepid(make_env(fake_proc.root)).state is SourceState.OK

    def test_degraded_when_hidepid_active(self, fake_proc):
        fake_proc.add_mounts("rw,nosuid,hidepid=invisible")

        status = probe_hidepid(make_env(fake_proc.root))

        assert status.state is SourceState.DEGRADED
        assert status.data["hidepid"] == "invisible"


class TestForeignProcessAccess:
    def test_ok_when_private_files_of_foreign_process_are_readable(self, fake_proc):
        fake_proc.add_process(1, uid=0, comm="systemd", private_readable=True)
        env = make_env(fake_proc.root)

        assert probe_foreign_exe(env).state is SourceState.OK
        assert probe_foreign_io(env).state is SourceState.OK
        assert probe_foreign_smaps(env).state is SourceState.OK

    @pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file permissions")
    def test_degraded_when_private_files_are_denied(self, fake_proc):
        fake_proc.add_process(1, uid=0, comm="systemd", private_readable=False, private_denied=True)
        env = make_env(fake_proc.root)

        assert probe_foreign_io(env).state is SourceState.DEGRADED
        assert probe_foreign_smaps(env).state is SourceState.DEGRADED

    def test_disabled_when_no_foreign_process_is_visible(self, fake_proc):
        fake_proc.add_process(42, uid=OWN_UID)

        status = probe_foreign_exe(make_env(fake_proc.root))

        assert status.state is SourceState.DISABLED

    @pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file permissions")
    def test_skips_own_processes_when_choosing_foreign_target(self, fake_proc):
        fake_proc.add_process(10, uid=OWN_UID, private_readable=True)
        fake_proc.add_process(20, uid=0, private_readable=False, private_denied=True)

        status = probe_foreign_io(make_env(fake_proc.root))

        assert status.state is SourceState.DEGRADED
        assert status.data["pid"] == 20


class TestCgroupAppScopes:
    def test_ok_and_counts_distinct_app_units(self, fake_proc):
        base = "0::/user.slice/user-1000.slice/user@1000.service/app.slice"
        fake_proc.add_process(10, cgroup=f"{base}/app-gnome-firefox-1234.scope")
        fake_proc.add_process(11, cgroup=f"{base}/app-gnome-firefox-1234.scope")
        fake_proc.add_process(12, cgroup=f"{base}/app-org.gnome.Terminal.slice/vte-spawn-ab.scope")
        fake_proc.add_process(13, cgroup="0::/system.slice/NetworkManager.service")

        status = probe_cgroup_app_scopes(make_env(fake_proc.root))

        assert status.state is SourceState.OK
        assert status.data["cgroup_v2"] is True
        assert status.data["app_units"] == 2

    def test_degraded_on_cgroup_v2_without_app_scopes(self, fake_proc):
        fake_proc.add_process(13, cgroup="0::/system.slice/NetworkManager.service")

        status = probe_cgroup_app_scopes(make_env(fake_proc.root))

        assert status.state is SourceState.DEGRADED
        assert status.data["app_units"] == 0

    def test_degraded_on_cgroup_v1(self, fake_proc):
        fake_proc.add_process(13, cgroup="12:cpu,cpuacct:/user.slice\n1:name=systemd:/user.slice")

        status = probe_cgroup_app_scopes(make_env(fake_proc.root))

        assert status.state is SourceState.DEGRADED
        assert status.data["cgroup_v2"] is False


class TestPsi:
    def test_ok_with_all_three_resources(self, fake_proc):
        fake_proc.add_psi("cpu", "memory", "io")

        status = probe_psi(make_env(fake_proc.root))

        assert status.state is SourceState.OK
        assert status.data["cpu_some_avg10"] == 1.5

    def test_degraded_with_partial_resources(self, fake_proc):
        fake_proc.add_psi("cpu")

        assert probe_psi(make_env(fake_proc.root)).state is SourceState.DEGRADED

    def test_disabled_without_pressure_dir(self, fake_proc):
        assert probe_psi(make_env(fake_proc.root)).state is SourceState.DISABLED


class TestMeminfo:
    def test_ok_with_memavailable(self, fake_proc):
        fake_proc.add_meminfo(available_kb=4_000_000)

        status = probe_meminfo(make_env(fake_proc.root))

        assert status.state is SourceState.OK
        assert status.data["mem_available_kb"] == 4_000_000

    def test_degraded_without_memavailable(self, fake_proc):
        fake_proc.add_meminfo(available_kb=None)

        assert probe_meminfo(make_env(fake_proc.root)).state is SourceState.DEGRADED


class TestCommandBackedProbes:
    def test_journald_disabled_when_journalctl_missing(self, fake_proc):
        assert probe_journald(make_env(fake_proc.root)).state is SourceState.DISABLED

    def test_journald_ok_when_system_journal_returns_entries(self, fake_proc):
        env = make_env(
            fake_proc.root,
            binaries={"journalctl": "/usr/bin/journalctl"},
            commands={"journalctl": CommandResult(0, '{"MESSAGE":"hi"}\n', "", 12.0)},
        )

        assert probe_journald(env).state is SourceState.OK

    def test_journald_degraded_when_permission_hint_is_printed(self, fake_proc):
        env = make_env(
            fake_proc.root,
            binaries={"journalctl": "/usr/bin/journalctl"},
            commands={
                "journalctl": CommandResult(
                    0, "", "Hint: You are currently not seeing messages from other users and the system.", 5.0
                )
            },
        )

        assert probe_journald(env).state is SourceState.DEGRADED

    def test_piper_found_under_alternate_binary_name(self, fake_proc):
        env = make_env(fake_proc.root, binaries={"piper-tts": "/usr/bin/piper-tts"})

        status = probe_tts_piper(env)

        assert status.state is SourceState.OK
        assert status.data["binary"] == "/usr/bin/piper-tts"


class TestDesktopEntries:
    def test_counts_entries_and_spanish_comments(self, fake_proc, tmp_path):
        apps = tmp_path / "applications"
        apps.mkdir()
        (apps / "firefox.desktop").write_text(
            "[Desktop Entry]\nName=Firefox\nComment=Browse the Web\nComment[es]=Navegue por la web\n"
        )
        (apps / "foo.desktop").write_text("[Desktop Entry]\nName=Foo\n")
        (apps / "README").write_text("not a desktop file")

        status = probe_desktop_entries(make_env(fake_proc.root, desktop_dirs=[apps, tmp_path / "missing"]))

        assert status.state is SourceState.OK
        assert status.data["entries"] == 2
        assert status.data["with_comment_es"] == 1


class TestRunAll:
    def test_a_crashing_probe_never_stops_the_others(self, fake_proc):
        def boom(env):
            raise RuntimeError("kaboom")

        statuses = run_all(make_env(fake_proc.root), probes=[("boom", boom), ("proc_listing", probe_proc_listing)])

        assert [s.source for s in statuses] == ["boom", "proc_listing"]
        assert statuses[0].state is SourceState.DISABLED
        assert "kaboom" in statuses[0].detail

    def test_default_probe_set_runs_on_an_empty_proc(self, fake_proc):
        statuses = run_all(make_env(fake_proc.root))

        assert len(statuses) >= 15
        assert len({s.source for s in statuses}) == len(statuses)


# --- review follow-ups ------------------------------------------------------

import errno as _errno
import os as _os
import sys as _sys

import pytest

from ecoprocesos.probe import capabilities as caps
from ecoprocesos.probe.capabilities import probe_mic_signal, probe_whatis, run_command

needs_non_root = pytest.mark.skipif(_os.geteuid() == 0, reason="root bypasses file permissions")


class TestRunCommand:
    def test_forces_c_locale_so_output_is_parseable(self):
        result = run_command([_sys.executable, "-c", "import os; print(os.environ['LC_ALL'])"], 5.0)

        assert result.stdout.strip() == "C"

    def test_undecodable_output_never_raises(self):
        result = run_command([_sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'\\xff\\xfe')"], 5.0)

        assert result.returncode == 0


class TestHidepidGroups:
    def test_last_proc_mount_wins(self, fake_proc):
        (fake_proc.root / "mounts").write_text(
            "proc /proc proc rw 0 0\nproc /proc proc rw,hidepid=2 0 0\n"
        )

        assert probe_hidepid(make_env(fake_proc.root)).state is SourceState.DEGRADED

    def test_ok_when_member_of_exempt_gid(self, fake_proc):
        fake_proc.add_mounts("rw,hidepid=2,gid=27")
        env = caps.ProbeEnv(proc_root=fake_proc.root, euid=OWN_UID, groups=(1000, 27))

        status = probe_hidepid(env)

        assert status.state is SourceState.OK
        assert status.data["exempt_gid"] == 27


class TestForeignAccessClassification:
    @needs_non_root
    def test_permission_denied_means_needs_privilege(self, fake_proc):
        pid_dir = fake_proc.add_process(1, uid=0, private_readable=True)
        (pid_dir / "io").chmod(0)

        status = probe_foreign_io(make_env(fake_proc.root))

        assert status.state is SourceState.DEGRADED
        assert "EACCES" in status.detail

    def test_vanished_file_tries_next_foreign_process(self, fake_proc):
        fake_proc.add_process(1, uid=0, private_readable=False)  # e.g. kernel thread without exe
        fake_proc.add_process(2, uid=0, private_readable=True)

        status = probe_foreign_exe(make_env(fake_proc.root))

        assert status.state is SourceState.OK
        assert status.data["pid"] == 2

    def test_exe_permission_error_is_degraded(self, fake_proc, monkeypatch):
        fake_proc.add_process(1, uid=0)

        def denied(path):
            raise PermissionError(_errno.EACCES, "denied")

        monkeypatch.setattr(caps.os, "readlink", denied)

        assert probe_foreign_exe(make_env(fake_proc.root)).state is SourceState.DEGRADED

    def test_disabled_when_every_candidate_is_inconclusive(self, fake_proc):
        fake_proc.add_process(1, uid=0, private_readable=False)

        assert probe_foreign_smaps(make_env(fake_proc.root)).state is SourceState.DISABLED


class TestMicSignal:
    def test_ignores_streams_recording_from_monitor_sources(self, fake_proc):
        def run(argv, timeout_s):
            if argv[-1] == "sources":
                return CommandResult(0, "50\talsa_output.pci.monitor\tPipeWire\n51\talsa_input.pci\tPipeWire\n", "", 1.0)
            return CommandResult(0, "7\t50\t80\tfloat32le 2ch\n8\t51\t81\ts16le 1ch\n", "", 1.0)

        env = caps.ProbeEnv(proc_root=fake_proc.root, which=lambda n: "/usr/bin/pactl", run=run, euid=OWN_UID)

        status = probe_mic_signal(env)

        assert status.state is SourceState.OK
        assert status.data["input_recordings"] == 1


class TestWhatis:
    def test_degraded_when_man_index_is_empty(self, fake_proc):
        env = make_env(
            fake_proc.root,
            binaries={"whatis": "/usr/bin/whatis"},
            commands={"whatis": CommandResult(16, "", "ls: nothing appropriate.", 1.0)},
        )

        assert probe_whatis(env).state is SourceState.DEGRADED

    def test_ok_when_lookup_succeeds(self, fake_proc):
        env = make_env(
            fake_proc.root,
            binaries={"whatis": "/usr/bin/whatis"},
            commands={"whatis": CommandResult(0, "ls (1) - list directory contents\n", "", 1.0)},
        )

        assert probe_whatis(env).state is SourceState.OK


class TestDesktopDedupe:
    def test_same_basename_in_two_dirs_counts_once(self, fake_proc, tmp_path):
        user, system = tmp_path / "user", tmp_path / "system"
        for d in (user, system):
            d.mkdir()
            (d / "firefox.desktop").write_text("[Desktop Entry]\nName=Firefox\n")

        status = probe_desktop_entries(make_env(fake_proc.root, desktop_dirs=[user, system]))

        assert status.data["entries"] == 1
