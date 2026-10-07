"""Shared fixtures: a fake /proc tree so Linux readers can be tested on any OS."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Optional

import pytest


class FakeProc:
    """Builds a minimal /proc-like directory tree under a temporary path."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True)

    def add_process(
        self,
        pid: int,
        *,
        comm: str = "bash",
        uid: int = 1000,
        ppid: int = 1,
        state: str = "S",
        cmdline: Iterable[str] = ("bash",),
        cgroup: str = "0::/user.slice/user-1000.slice/session-2.scope",
        private_readable: bool = True,
        private_denied: bool = False,
        exe: str = "/usr/bin/bash",
    ) -> Path:
        pid_dir = self.root / str(pid)
        pid_dir.mkdir()
        (pid_dir / "stat").write_text(
            f"{pid} ({comm}) {state} {ppid} {pid} {pid} 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 100 1000000 200\n"
        )
        (pid_dir / "status").write_text(
            f"Name:\t{comm}\nState:\t{state}\nPPid:\t{ppid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
        )
        (pid_dir / "cmdline").write_bytes(b"\0".join(a.encode() for a in cmdline) + b"\0")
        (pid_dir / "cgroup").write_text(cgroup + "\n")
        if private_readable:
            (pid_dir / "io").write_text("rchar: 100\nwchar: 50\nread_bytes: 0\nwrite_bytes: 0\n")
            (pid_dir / "smaps_rollup").write_text("Rss: 1024 kB\nPss: 512 kB\n")
            os.symlink(exe, pid_dir / "exe")
        if private_denied:  # what an unprivileged user sees for another user's process
            for name in ("io", "smaps_rollup"):
                (pid_dir / name).write_text("")
                (pid_dir / name).chmod(0)
        return pid_dir

    def set_self(self, pid: int) -> None:
        os.symlink(str(pid), self.root / "self")

    def add_psi(self, *resources: str) -> None:
        pressure = self.root / "pressure"
        pressure.mkdir(exist_ok=True)
        for resource in resources:
            (pressure / resource).write_text(
                "some avg10=1.50 avg60=0.80 avg300=0.20 total=12345\n"
                "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
            )

    def add_meminfo(self, *, available_kb: Optional[int] = 4_000_000) -> None:
        lines = ["MemTotal:       16000000 kB", "MemFree:         1000000 kB"]
        if available_kb is not None:
            lines.append(f"MemAvailable:   {available_kb} kB")
        (self.root / "meminfo").write_text("\n".join(lines) + "\n")

    def add_mounts(self, proc_options: str = "rw,nosuid,nodev,noexec,relatime") -> None:
        (self.root / "mounts").write_text(
            "sysfs /sys sysfs rw,nosuid 0 0\n"
            f"proc /proc proc {proc_options} 0 0\n"
        )


@pytest.fixture
def fake_proc(tmp_path: Path) -> FakeProc:
    return FakeProc(tmp_path / "proc")
