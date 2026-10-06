"""Read aggregate Docker job counters; unavailable evidence is a hard error.

Memory peak is kernel charged memory (including owned file cache), distinct
from aggregate RSS and shared pages charged elsewhere. No sampling proxy
is substituted for the peak counter. CPU includes every process in the cgroup.
"""

from pathlib import Path, PurePosixPath
import re


def mount_relative(membership, mount_root, mount_point):
    path, root = PurePosixPath(membership), PurePosixPath(mount_root)
    if not path.is_absolute() or ".." in path.parts or ".." in root.parts:
        raise ValueError("unsafe cgroup membership")
    return Path(mount_point) / path.relative_to(root)


def group_paths(pid, proc=Path("/proc")):
    memberships = {}
    for line in (proc / str(pid) / "cgroup").read_text().splitlines():
        _id, controllers, membership = line.split(":", 2)
        memberships.update({name: membership for name in controllers.split(",")})
    mounts = []
    for line in (proc / "self/mountinfo").read_text().splitlines():
        before, after = line.split(" - ", 1)
        fields, filesystem = before.split(), after.split()
        if filesystem[0] in {"cgroup", "cgroup2"}:
            mounts.append((fields[3], fields[4], filesystem[0], filesystem[2].split(",")))
    for root, point, kind, _controllers in mounts:
        if kind == "cgroup2" and "" in memberships:
            return {"version": 2, "unified": mount_relative(memberships[""], root, point)}
    result = {"version": 1}
    for root, point, kind, controllers in mounts:
        if kind != "cgroup":
            continue
        for name in ("memory", "cpuacct", "cpu", "cpuset", "pids"):
            if name in controllers and name in memberships:
                result[name] = mount_relative(memberships[name], root, point)
    if not {"memory", "cpuacct"} <= result.keys():
        raise RuntimeError("aggregate cgroup CPU/peak memory counters unavailable")
    return result


def cpu_set(value):
    result = set()
    for item in value.strip().split(","):
        first, _, last = item.partition("-")
        result.update(range(int(first), int(last or first) + 1))
    return result


def enforcement(paths, pid, identifier, selected_cpus, memory_bytes):
    """Refuse shared/wrong cgroups and verify actual kernel job limits."""
    membership = (Path("/proc") / str(pid) / "cgroup").read_text()
    if (
        not re.fullmatch("[0-9a-f]{64}", identifier)
        or identifier not in membership
        or not all(identifier in str(path) for key, path in paths.items() if key != "version")
    ):
        raise RuntimeError("container PID is not in its unique cgroup")
    if paths["version"] == 2:
        root = paths["unified"]
        quota, period = (root / "cpu.max").read_text().split()
        limits = {
            "cpu_quota": int(quota),
            "cpu_period": int(period),
            "memory_bytes": int((root / "memory.max").read_text()),
            "memory_swap_bytes": int((root / "memory.swap.max").read_text()),
            "pids": int((root / "pids.max").read_text()),
            "cpu_slots": sorted(cpu_set((root / "cpuset.cpus.effective").read_text())),
        }
    else:
        cpu, memory, pids, cpuset = (paths[name] for name in ("cpu", "memory", "pids", "cpuset"))
        maximum = int((memory / "memory.limit_in_bytes").read_text())
        limits = {
            "cpu_quota": int((cpu / "cpu.cfs_quota_us").read_text()),
            "cpu_period": int((cpu / "cpu.cfs_period_us").read_text()),
            "memory_bytes": maximum,
            "memory_swap_bytes": int((memory / "memory.memsw.limit_in_bytes").read_text()) - maximum,
            "pids": int((pids / "pids.max").read_text()),
            "cpu_slots": sorted(cpu_set((cpuset / "cpuset.cpus").read_text())),
        }
    if (
        limits["cpu_quota"] != 2 * limits["cpu_period"]
        or limits["memory_bytes"] != memory_bytes
        or limits["memory_swap_bytes"] != 0
        or limits["pids"] != 256
        or limits["cpu_slots"] != selected_cpus
    ):
        raise RuntimeError("kernel job limits differ from benchmark configuration")
    return {"limits": limits, "membership": membership, "paths": {key: str(value) for key, value in paths.items()}}


def counters(paths):
    if paths["version"] == 2:
        root = paths["unified"]
        cpu = dict(line.split() for line in (root / "cpu.stat").read_text().splitlines())
        events = dict(line.split() for line in (root / "memory.events").read_text().splitlines())
        return {
            "cpu_seconds": int(cpu["usage_usec"]) / 1_000_000,
            "peak_charged_memory_bytes": int((root / "memory.peak").read_text()),
            "oom_kills": int(events["oom_kill"]),
        }
    return {
        "cpu_seconds": int((paths["cpuacct"] / "cpuacct.usage").read_text()) / 1_000_000_000,
        "peak_charged_memory_bytes": int((paths["memory"] / "memory.max_usage_in_bytes").read_text()),
        "memory_limit_failures": int((paths["memory"] / "memory.failcnt").read_text()),
    }
