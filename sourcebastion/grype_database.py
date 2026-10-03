"""Refresh external advisories in a source-free process, then publish a snapshot.

Run with the scanner image's Python: python -m sourcebastion.grype_database /db.
Scans bind the resolved current directory read-only; refresh never edits it.
"""
import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import uuid


def refresh(directory: Path, *, runner=subprocess.run, now=None) -> Path:
    if os.getuid() == 0:
        raise ValueError("database refresh must run as an unprivileged user")
    if not directory.is_absolute():
        raise ValueError("database directory must be absolute")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o002
            or (info.st_mode & 0o020 and info.st_gid != os.getgid())):
        raise ValueError("database directory must be owned by the updater and not writable by other identities")
    timestamp = now or datetime.now(timezone.utc)
    lock_fd = os.open(directory / ".refresh.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        snapshot = Path(tempfile.mkdtemp(prefix="snapshot-", dir=directory))
        link = directory / (".current-" + uuid.uuid4().hex)
        published = False
        try:
            env = dict(os.environ, GRYPE_DB_CACHE_DIR=str(snapshot),
                       GRYPE_DB_AUTO_UPDATE="false", GRYPE_CHECK_FOR_APP_UPDATE="false",
                       GRYPE_DB_VALIDATE_AGE="true", GRYPE_DB_MAX_ALLOWED_BUILT_AGE="120h",
                       GRYPE_DB_VALIDATE_BY_HASH_ON_START="true")
            for command in (["grype", "db", "update"], ["grype", "db", "status", "-o", "json"]):
                result = runner(command, capture_output=True, text=True, env=env, timeout=360, check=False)
                if result.returncode != 0:
                    raise RuntimeError("Grype database refresh or validation failed")
            status = json.loads(result.stdout)
            if not isinstance(status, dict):
                raise ValueError("Grype database status must be an object")
            receipt = snapshot / "snapshot.json"
            fd = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as handle:
                json.dump({"refreshed_at": timestamp.isoformat(), "database": status}, handle)
                handle.flush()
                os.fsync(handle.fileno())
            link.symlink_to(snapshot.name, target_is_directory=True)
            os.replace(link, directory / "current")
            published = True
            root_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(root_fd)
            finally:
                os.close(root_fd)
            # Keep seven days: far longer than the worker's bounded scan lease.
            # The current generation and unfinished/foreign directories survive.
            for candidate in directory.glob("snapshot-*"):
                if candidate == snapshot or candidate.is_symlink():
                    continue
                try:
                    saved = json.loads((candidate / "snapshot.json").read_text())
                    created = datetime.fromisoformat(saved["refreshed_at"])
                    if created.tzinfo is not None and created < timestamp - timedelta(days=7):
                        shutil.rmtree(candidate)
                except (OSError, ValueError, KeyError, TypeError):
                    continue
            return snapshot
        finally:
            link.unlink(missing_ok=True)
            if not published:
                shutil.rmtree(snapshot)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        snapshot = refresh(args.directory)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        parser.exit(1, "Grype database refresh failed; previous snapshot retained\n")
    print(json.dumps({"generation": snapshot.name, "validated": True}))


if __name__ == "__main__":
    main()
