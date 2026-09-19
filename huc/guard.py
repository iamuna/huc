from __future__ import annotations

import logging
import os
import time

import psutil

from .blocklist import BlockList, CRITICAL_NAMES
from .paths import log_path

POLL_SECONDS = 0.35


def configure_logging() -> None:
    logging.basicConfig(
        filename=log_path(),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def run_guard(poll_seconds: float = POLL_SECONDS) -> None:
    configure_logging()
    blocklist = BlockList()
    seen: dict[int, tuple[float, bool]] = {}
    last_reload = 0.0

    logging.info("HUC guard started")
    while True:
        now = time.monotonic()
        if now - last_reload >= 2.0:
            blocklist.reload()
            last_reload = now

        live: set[int] = set()
        for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
            pid = proc.info["pid"]
            if pid in {0, 4, os.getpid()}:
                continue
            live.add(pid)
            name = (proc.info.get("name") or "").lower()
            if name in CRITICAL_NAMES:
                continue
            created = float(proc.info.get("create_time") or 0.0)
            cached = seen.get(pid)
            if cached and cached[0] == created:
                if cached[1]:
                    try:
                        proc.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                continue

            path = proc.info.get("exe") or ""
            rule = blocklist.match(path, check_hash=True)
            blocked = rule is not None
            seen[pid] = (created, blocked)
            if blocked:
                try:
                    proc.kill()
                    logging.warning(
                        "Blocked pid=%s name=%s path=%s rule=%s",
                        pid, name, path, rule.sha256[:12],
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
                    logging.warning(
                        "Could not kill blocked pid=%s path=%s: %s",
                        pid, path, exc,
                    )

        for pid in set(seen) - live:
            seen.pop(pid, None)
        time.sleep(poll_seconds)


def main() -> int:
    try:
        run_guard()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
