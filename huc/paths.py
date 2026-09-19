from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "HUC"


def data_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("PROGRAMDATA", str(Path.home() / "AppData" / "Local")))
    else:
        base = Path.home() / ".local" / "share"
    path = base / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def blocklist_path() -> Path:
    return data_dir() / "blocklist.json"


def log_path() -> Path:
    return data_dir() / "guard.log"
