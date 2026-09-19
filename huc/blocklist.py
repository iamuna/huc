from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .paths import blocklist_path

CRITICAL_NAMES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe",
}


def normalize_path(value: str | os.PathLike[str] | None) -> str:
    if not value:
        return ""
    return os.path.normcase(os.path.abspath(os.fspath(value)))


def sha256_file(path: str | os.PathLike[str], chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class BlockRule:
    name: str
    path: str
    sha256: str
    added_at: str

    @staticmethod
    def from_path(path: str | os.PathLike[str]) -> "BlockRule":
        resolved = normalize_path(path)
        if not resolved or not os.path.isfile(resolved):
            raise FileNotFoundError(resolved or str(path))
        name = os.path.basename(resolved)
        if name.lower() in CRITICAL_NAMES:
            raise ValueError(f"Refusing to block protected Windows process: {name}")
        return BlockRule(
            name=name,
            path=resolved,
            sha256=sha256_file(resolved),
            added_at=datetime.now(timezone.utc).isoformat(),
        )


class BlockList:
    def __init__(self, path: Path | None = None):
        self.path = path or blocklist_path()
        self._lock = threading.RLock()
        self._rules: list[BlockRule] = []
        self.reload()

    def reload(self) -> None:
        with self._lock:
            if not self.path.exists():
                self._rules = []
                return
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                self._rules = [BlockRule(**item) for item in raw.get("rules", [])]
            except (OSError, json.JSONDecodeError, TypeError):
                self._rules = []

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": 1, "rules": [asdict(r) for r in self._rules]}
        fd, tmp_name = tempfile.mkstemp(prefix="huc-", suffix=".json", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, self.path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def rules(self) -> tuple[BlockRule, ...]:
        with self._lock:
            return tuple(self._rules)

    def add_path(self, path: str | os.PathLike[str]) -> BlockRule:
        rule = BlockRule.from_path(path)
        with self._lock:
            self._rules = [
                r for r in self._rules
                if r.path != rule.path and r.sha256 != rule.sha256
            ]
            self._rules.append(rule)
            self._save()
        return rule

    def remove(self, *, path: str | None = None, sha256: str | None = None) -> int:
        npath = normalize_path(path) if path else None
        with self._lock:
            before = len(self._rules)
            self._rules = [
                r for r in self._rules
                if not ((npath and r.path == npath) or (sha256 and r.sha256 == sha256))
            ]
            removed = before - len(self._rules)
            if removed:
                self._save()
            return removed

    def path_blocked(self, path: str | None) -> bool:
        npath = normalize_path(path)
        if not npath:
            return False
        with self._lock:
            return any(r.path == npath for r in self._rules)

    def match(self, path: str | None, *, check_hash: bool = True) -> BlockRule | None:
        npath = normalize_path(path)
        if not npath:
            return None
        with self._lock:
            rules = tuple(self._rules)
        for rule in rules:
            if rule.path == npath:
                return rule
        if not check_hash or not os.path.isfile(npath):
            return None
        try:
            digest = sha256_file(npath)
        except OSError:
            return None
        return next((rule for rule in rules if rule.sha256 == digest), None)
