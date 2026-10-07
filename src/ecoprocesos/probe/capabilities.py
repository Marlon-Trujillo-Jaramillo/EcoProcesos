"""Startup capability probe: discovers which Linux data sources are usable.

Every probe is isolated: a failure in one never prevents the others from
running, and each yields exactly one SourceStatus (OK / DEGRADED / DISABLED).
All filesystem access goes through ProbeEnv roots and all commands through
ProbeEnv.run, so the probes can be tested against a fake /proc on any OS.
"""

from __future__ import annotations

import enum
import errno
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple


class SourceState(str, enum.Enum):
    OK = "ok"
    DEGRADED = "degraded"
    DISABLED = "disabled"


@dataclass(frozen=True)
class SourceStatus:
    source: str
    state: SourceState
    detail: str = ""
    data: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {"source": self.source, "state": self.state.value, "detail": self.detail, "data": self.data}


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    elapsed_ms: float


def run_command(argv: Sequence[str], timeout_s: float) -> CommandResult:
    """Run a command with the C locale (tools like pactl localize their labels)."""
    start = time.perf_counter()
    env = {**os.environ, "LC_ALL": "C"}
    try:
        proc = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            errors="replace",
            env=env,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(-1, "", f"timeout after {timeout_s}s", (time.perf_counter() - start) * 1000)
    except OSError as exc:
        return CommandResult(-1, "", str(exc), (time.perf_counter() - start) * 1000)
    return CommandResult(proc.returncode, proc.stdout, proc.stderr, (time.perf_counter() - start) * 1000)


def _default_desktop_dirs() -> Tuple[Path, ...]:
    data_home = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    data_dirs = [d for d in (os.environ.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share").split(":") if d]
    # Flatpak and Snap exports may be missing from XDG_DATA_DIRS outside a login session.
    extra = [str(data_home / "flatpak/exports/share"), "/var/lib/flatpak/exports/share", "/var/lib/snapd/desktop"]
    ordered = list(dict.fromkeys([str(data_home), *data_dirs, *extra]))
    return tuple(Path(d) / "applications" for d in ordered)


@dataclass(frozen=True)
class ProbeEnv:
    proc_root: Path = Path("/proc")
    sys_root: Path = Path("/sys")
    desktop_dirs: Tuple[Path, ...] = field(default_factory=_default_desktop_dirs)
    euid: int = field(default_factory=os.geteuid)
    groups: Tuple[int, ...] = field(default_factory=lambda: tuple(os.getgroups()))
    which: Callable[[str], Optional[str]] = shutil.which
    run: Callable[[Sequence[str], float], CommandResult] = run_command
    command_timeout_s: float = 5.0


Probe = Callable[[ProbeEnv], SourceStatus]


# --- /proc helpers -----------------------------------------------------------


def _pid_dirs(proc_root: Path) -> Iterator[Path]:
    for entry in os.scandir(proc_root):
        if entry.name.isdigit():
            yield Path(entry.path)


def _real_uid(pid_dir: Path) -> Optional[int]:
    try:
        for line in (pid_dir / "status").read_text().splitlines():
            if line.startswith("Uid:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def _foreign_pids(env: ProbeEnv) -> Iterator[Path]:
    """Visible processes owned by another user, lowest PID first (usually PID 1, root)."""
    for pid_dir in sorted(_pid_dirs(env.proc_root), key=lambda p: int(p.name)):
        uid = _real_uid(pid_dir)
        if uid is not None and uid != env.euid:
            yield pid_dir


def _errno_name(exc: OSError) -> str:
    return errno.errorcode.get(exc.errno or 0, type(exc).__name__)


_DENIED = (errno.EACCES, errno.EPERM)
_MAX_FOREIGN_CANDIDATES = 20


def _probe_foreign_file(source: str, env: ProbeEnv, read: Callable[[Path], object], why: str) -> SourceStatus:
    """Only EACCES/EPERM mean "needs privilege"; vanished processes or missing files
    (kernel threads, old kernels) are inconclusive, so the next candidate is tried."""
    tried = 0
    for pid_dir in _foreign_pids(env):
        if tried >= _MAX_FOREIGN_CANDIDATES:
            break
        tried += 1
        data: Dict[str, object] = {"pid": int(pid_dir.name), "euid": env.euid}
        try:
            read(pid_dir)
        except OSError as exc:
            if exc.errno in _DENIED:
                return SourceStatus(source, SourceState.DEGRADED, f"{_errno_name(exc)}: {why}", data)
            continue
        detail = "readable" + (" (running as root: not representative)" if env.euid == 0 else "")
        return SourceStatus(source, SourceState.OK, detail, data)
    if tried == 0:
        return SourceStatus(source, SourceState.DISABLED, "no process owned by another user is visible to test")
    return SourceStatus(source, SourceState.DISABLED, f"inconclusive: file missing on {tried} candidate processes")


# --- probes ------------------------------------------------------------------


def probe_proc_listing(env: ProbeEnv) -> SourceStatus:
    if not env.proc_root.is_dir():
        return SourceStatus("proc_listing", SourceState.DISABLED, f"{env.proc_root} not found")
    count = sum(1 for _ in _pid_dirs(env.proc_root))
    state = SourceState.OK if count else SourceState.DISABLED
    return SourceStatus("proc_listing", state, f"{count} processes visible", {"visible_processes": count})


def probe_hidepid(env: ProbeEnv) -> SourceStatus:
    try:
        mounts = (env.proc_root / "mounts").read_text()
    except OSError as exc:
        return SourceStatus("hidepid", SourceState.DEGRADED, f"cannot read mounts ({_errno_name(exc)}); unknown")
    options: Optional[str] = None
    for line in mounts.splitlines():  # the last /proc mount is the effective one
        fields = line.split()
        if len(fields) >= 4 and fields[2] == "proc" and fields[1] == "/proc":
            options = fields[3]
    if options is None:
        return SourceStatus("hidepid", SourceState.DEGRADED, "/proc mount entry not found; unknown")
    match = re.search(r"(?:^|,)hidepid=([^,]+)", options)
    value = match.group(1) if match else "0"
    data: Dict[str, object] = {"hidepid": value}
    if value in ("0", "off"):
        return SourceStatus("hidepid", SourceState.OK, "all processes visible", data)
    gid_match = re.search(r"(?:^|,)gid=(\d+)", options)
    if gid_match and int(gid_match.group(1)) in env.groups:
        data["exempt_gid"] = int(gid_match.group(1))
        return SourceStatus("hidepid", SourceState.OK, f"hidepid={value}, but user is in exempt gid", data)
    return SourceStatus("hidepid", SourceState.DEGRADED, f"hidepid={value}: other users' processes are hidden", data)


def probe_foreign_cmdline(env: ProbeEnv) -> SourceStatus:
    return _probe_foreign_file(
        "proc_cmdline_foreign", env, lambda p: (p / "cmdline").read_bytes(), "cannot identify other users' programs"
    )


def probe_foreign_exe(env: ProbeEnv) -> SourceStatus:
    return _probe_foreign_file(
        "proc_exe_foreign", env, lambda p: os.readlink(p / "exe"), "fallback to cmdline[0] + which (basic mode)"
    )


def probe_foreign_io(env: ProbeEnv) -> SourceStatus:
    return _probe_foreign_file(
        "proc_io_foreign", env, lambda p: (p / "io").read_text(), "per-process disk I/O needs the helper (full mode)"
    )


def probe_foreign_smaps(env: ProbeEnv) -> SourceStatus:
    return _probe_foreign_file(
        "proc_smaps_foreign", env, lambda p: (p / "smaps_rollup").read_text(), "PSS of other users' processes needs the helper"
    )


_APP_UNIT = re.compile(r"^app-.+\.(scope|service|slice)$")


def probe_cgroup_app_scopes(env: ProbeEnv) -> SourceStatus:
    v2 = False
    readable = 0
    app_units = set()
    for pid_dir in _pid_dirs(env.proc_root):
        try:
            lines = (pid_dir / "cgroup").read_text().splitlines()
        except OSError:
            continue
        readable += 1
        for line in lines:
            if not line.startswith("0::"):
                continue
            v2 = True
            for part in line[3:].split("/"):
                if _APP_UNIT.match(part):
                    app_units.add(part)
                    break
    data: Dict[str, object] = {"cgroup_v2": v2, "app_units": len(app_units), "readable": readable}
    if readable == 0:
        return SourceStatus("cgroup_app_scopes", SourceState.DISABLED, "no readable /proc/PID/cgroup", data)
    if not v2:
        return SourceStatus("cgroup_app_scopes", SourceState.DEGRADED, "cgroup v1: group by process name instead", data)
    if not app_units:
        return SourceStatus(
            "cgroup_app_scopes", SourceState.DEGRADED, "no app-*.scope units (no desktop session?): group by name", data
        )
    return SourceStatus("cgroup_app_scopes", SourceState.OK, f"{len(app_units)} desktop app units", data)


_PSI_RESOURCES = ("cpu", "memory", "io")


def probe_psi(env: ProbeEnv) -> SourceStatus:
    data: Dict[str, object] = {}
    available: List[str] = []
    for resource in _PSI_RESOURCES:
        try:
            text = (env.proc_root / "pressure" / resource).read_text()
        except OSError:
            continue
        match = re.search(r"^some avg10=([\d.]+)", text, re.MULTILINE)
        if match:
            available.append(resource)
            data[f"{resource}_some_avg10"] = float(match.group(1))
    if not available:
        return SourceStatus(
            "psi", SourceState.DISABLED, "PSI unavailable: kernel lacks CONFIG_PSI or needs the psi=1 boot parameter"
        )
    state = SourceState.OK if len(available) == len(_PSI_RESOURCES) else SourceState.DEGRADED
    return SourceStatus("psi", state, ", ".join(available), data)


def probe_meminfo(env: ProbeEnv) -> SourceStatus:
    try:
        text = (env.proc_root / "meminfo").read_text()
    except OSError as exc:
        return SourceStatus("meminfo", SourceState.DISABLED, _errno_name(exc))
    match = re.search(r"^MemAvailable:\s+(\d+) kB", text, re.MULTILINE)
    if not match:
        return SourceStatus("meminfo", SourceState.DEGRADED, "MemAvailable missing: cannot judge real memory pressure")
    kb = int(match.group(1))
    return SourceStatus("meminfo", SourceState.OK, f"MemAvailable {kb // 1024} MiB", {"mem_available_kb": kb})


def _missing(source: str, *names: str) -> SourceStatus:
    return SourceStatus(source, SourceState.DISABLED, f"not installed: {' / '.join(names)}")


def _first_binary(env: ProbeEnv, *names: str) -> Optional[str]:
    for name in names:
        path = env.which(name)
        if path:
            return path
    return None


def probe_journald(env: ProbeEnv) -> SourceStatus:
    binary = _first_binary(env, "journalctl")
    if not binary:
        return _missing("journald", "journalctl")
    # No -q: the "not seeing messages from other users and the system" hint must reach stderr.
    result = env.run([binary, "--system", "-n", "1", "--no-pager", "-o", "json"], env.command_timeout_s)
    groups = _group_names()
    data: Dict[str, object] = {"elapsed_ms": round(result.elapsed_ms, 1), "groups": groups}
    if result.returncode == 0 and result.stdout.strip() and "not seeing" not in result.stderr:
        return SourceStatus("journald", SourceState.OK, "system journal readable", data)
    if not {"adm", "systemd-journal", "wheel"} & set(groups):
        return SourceStatus("journald", SourceState.DEGRADED, "user not in systemd-journal/adm: system journal hidden", data)
    hint = (result.stderr.strip().splitlines() or ["no entries returned"])[0]
    return SourceStatus("journald", SourceState.DEGRADED, hint[:200], data)


def _group_names() -> List[str]:
    try:
        import grp

        return sorted({grp.getgrgid(g).gr_name for g in os.getgroups()})
    except (ImportError, KeyError, OSError):
        return []


def _systemd_units_probe(source: str, *scope: str) -> Probe:
    def probe(env: ProbeEnv) -> SourceStatus:
        binary = _first_binary(env, "systemctl")
        if not binary:
            return _missing(source, "systemctl")
        argv = [binary, *scope, "list-units", "--no-pager", "--plain", "--no-legend"]
        result = env.run(argv, env.command_timeout_s)
        if result.returncode != 0:
            return SourceStatus(source, SourceState.DEGRADED, result.stderr.strip()[:200])
        units = sum(1 for line in result.stdout.splitlines() if line.strip())
        data = {"units": units, "elapsed_ms": round(result.elapsed_ms, 1)}
        return SourceStatus(source, SourceState.OK, f"{units} units in {result.elapsed_ms:.0f} ms", data)

    probe.__name__ = f"probe_{source}"
    return probe


probe_systemd_units = _systemd_units_probe("systemd_units")
# Desktop app-*.scope units live in the user manager, not the system one.
probe_systemd_user_units = _systemd_units_probe("systemd_user_units", "--user")


def probe_audio_server(env: ProbeEnv) -> SourceStatus:
    binary = _first_binary(env, "pactl")
    if not binary:
        return _missing("audio_server", "pactl")
    result = env.run([binary, "info"], env.command_timeout_s)
    match = re.search(r"^Server Name:\s*(.+)$", result.stdout, re.MULTILINE)
    if result.returncode != 0 or not match:
        return SourceStatus("audio_server", SourceState.DEGRADED, "pactl present but no PulseAudio-protocol server")
    return SourceStatus("audio_server", SourceState.OK, match.group(1).strip(), {"server": match.group(1).strip()})


def probe_mic_signal(env: ProbeEnv) -> SourceStatus:
    binary = _first_binary(env, "pactl")
    if not binary:
        return _missing("mic_in_use_signal", "pactl")
    sources = env.run([binary, "list", "short", "sources"], env.command_timeout_s)
    outputs = env.run([binary, "list", "short", "source-outputs"], env.command_timeout_s)
    if sources.returncode != 0 or outputs.returncode != 0:
        error = (sources.stderr or outputs.stderr).strip()[:200]
        return SourceStatus("mic_in_use_signal", SourceState.DEGRADED, error)
    # Recordings from ".monitor" sources capture speaker output (volume meters), not a microphone.
    monitors = {
        fields[0]
        for fields in (line.split("\t") for line in sources.stdout.splitlines())
        if len(fields) > 1 and fields[1].endswith(".monitor")
    }
    recordings = [line.split("\t") for line in outputs.stdout.splitlines() if line.strip()]
    inputs = sum(1 for fields in recordings if len(fields) > 1 and fields[1] not in monitors)
    data = {"source_outputs": len(recordings), "input_recordings": inputs}
    return SourceStatus("mic_in_use_signal", SourceState.OK, f"{inputs} recordings from input devices", data)


def _binary_probe(source: str, *names: str) -> Probe:
    def probe(env: ProbeEnv) -> SourceStatus:
        path = _first_binary(env, *names)
        if not path:
            return _missing(source, *names)
        return SourceStatus(source, SourceState.OK, path, {"binary": path})

    probe.__name__ = f"probe_{source}"
    return probe


probe_tts_piper = _binary_probe("tts_piper", "piper", "piper-tts")
probe_tts_espeak = _binary_probe("tts_espeak", "espeak-ng", "spd-say")
probe_package_manager = _binary_probe("package_manager", "dpkg-query", "rpm", "pacman")
probe_gamemode = _binary_probe("gamemode", "gamemoded")


def probe_whatis(env: ProbeEnv) -> SourceStatus:
    binary = _first_binary(env, "whatis")
    if not binary:
        return _missing("whatis", "whatis")
    result = env.run([binary, "ls"], env.command_timeout_s)
    if result.returncode != 0 or not result.stdout.strip():
        return SourceStatus("whatis", SourceState.DEGRADED, "man index empty or missing (minimal install?)")
    return SourceStatus("whatis", SourceState.OK, result.stdout.strip().splitlines()[0], {"binary": binary})


def probe_desktop_entries(env: ProbeEnv) -> SourceStatus:
    seen = set()  # earlier dirs shadow later ones with the same file name (XDG precedence)
    with_comment_es = 0
    for directory in env.desktop_dirs:
        if not directory.is_dir():
            continue
        for path in directory.glob("*.desktop"):
            if path.name in seen:
                continue
            seen.add(path.name)
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if re.search(r"^Comment\[es(_[A-Z]{2})?\]=", text, re.MULTILINE):
                with_comment_es += 1
    entries = len(seen)
    data = {"entries": entries, "with_comment_es": with_comment_es}
    if not entries:
        return SourceStatus("desktop_entries", SourceState.DISABLED, "no .desktop files found", data)
    return SourceStatus("desktop_entries", SourceState.OK, f"{entries} entries, {with_comment_es} with Spanish comment", data)


def probe_battery(env: ProbeEnv) -> SourceStatus:
    supplies = env.sys_root / "class" / "power_supply"
    if not supplies.is_dir():
        return SourceStatus("battery", SourceState.DISABLED, "no power_supply class")
    for supply in supplies.iterdir():
        try:
            if (supply / "type").read_text().strip() == "Battery":
                return SourceStatus("battery", SourceState.OK, supply.name, {"name": supply.name})
        except OSError:
            continue
    return SourceStatus("battery", SourceState.DISABLED, "no battery (desktop or VM)")


def probe_lsm(env: ProbeEnv) -> SourceStatus:
    data: Dict[str, object] = {}
    try:
        data["lsm"] = (env.sys_root / "kernel" / "security" / "lsm").read_text().strip()
    except OSError:
        pass
    try:
        data["selinux_enforcing"] = (env.sys_root / "fs" / "selinux" / "enforce").read_text().strip() == "1"
    except OSError:
        pass
    if not data:
        return SourceStatus("lsm", SourceState.DEGRADED, "could not determine active security modules")
    return SourceStatus("lsm", SourceState.OK, str(data.get("lsm", "")), data)


DEFAULT_PROBES: Tuple[Tuple[str, Probe], ...] = (
    ("proc_listing", probe_proc_listing),
    ("hidepid", probe_hidepid),
    ("proc_cmdline_foreign", probe_foreign_cmdline),
    ("proc_exe_foreign", probe_foreign_exe),
    ("proc_io_foreign", probe_foreign_io),
    ("proc_smaps_foreign", probe_foreign_smaps),
    ("cgroup_app_scopes", probe_cgroup_app_scopes),
    ("psi", probe_psi),
    ("meminfo", probe_meminfo),
    ("journald", probe_journald),
    ("systemd_units", probe_systemd_units),
    ("systemd_user_units", probe_systemd_user_units),
    ("audio_server", probe_audio_server),
    ("mic_in_use_signal", probe_mic_signal),
    ("tts_piper", probe_tts_piper),
    ("tts_espeak", probe_tts_espeak),
    ("package_manager", probe_package_manager),
    ("whatis", probe_whatis),
    ("gamemode", probe_gamemode),
    ("desktop_entries", probe_desktop_entries),
    ("battery", probe_battery),
    ("lsm", probe_lsm),
)


def run_all(env: ProbeEnv, probes: Sequence[Tuple[str, Probe]] = DEFAULT_PROBES) -> List[SourceStatus]:
    statuses: List[SourceStatus] = []
    for name, probe in probes:
        try:
            statuses.append(probe(env))
        except Exception as exc:  # noqa: BLE001 - one broken probe must never stop the rest
            statuses.append(SourceStatus(name, SourceState.DISABLED, f"probe crashed: {type(exc).__name__}: {exc}"))
    return statuses
