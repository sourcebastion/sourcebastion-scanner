"""Read aggregate Docker job counters; unavailable evidence is a hard error.

Memory peak is kernel charged memory (including owned file cache), distinct
from aggregate RSS and shared pages charged elsewhere. No sampling proxy
is substituted for the peak counter. CPU includes every process in the cgroup.
"""

from pathlib import Path, PurePosixPath


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
        for name in ("memory", "cpuacct"):
            if name in controllers and name in memberships:
                result[name] = mount_relative(memberships[name], root, point)
    if not {"memory", "cpuacct"} <= result.keys():
        raise RuntimeError("aggregate cgroup CPU/peak memory counters unavailable")
    return result


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
