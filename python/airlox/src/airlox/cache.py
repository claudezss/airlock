"""Local session cache.

Mirrors the relay's layout: the events as received and each blob as
ciphertext. The session key is never written here; reopening the invite
supplies it. ``identity-<role>.json`` holds this client's participant seed and
relay token for that role so it rejoins as the same participant, and is
readable only by the current user.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Iterator, Optional

# Session ids as the core defines them: "ax_" and 26 base32 characters.
_SESSION_ID = re.compile(r"ax_[a-z2-7]{26}")
# An item id (16 bytes, base64url): the only names blob files may have.
_ITEM_ID = re.compile(r"[A-Za-z0-9_-]{22}")


def default_root() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "airlox"


def _write_atomic(path: Path, data: bytes, mode: int = 0o600) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


class Cache:
    def __init__(self, root: Path, session_id: str) -> None:
        self.dir = Path(root) / session_id
        (self.dir / "blobs").mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)

    # identity --------------------------------------------------------
    def load_identity(self, role: str) -> Optional[dict]:
        p = self.dir / f"identity-{role}.json"
        return json.loads(p.read_text()) if p.exists() else None

    def save_identity(self, role: str, identity: dict) -> None:
        _write_atomic(self.dir / f"identity-{role}.json", json.dumps(identity).encode())

    # manifest --------------------------------------------------------
    def load_manifest(self) -> Optional[str]:
        p = self.dir / "manifest.json"
        return p.read_text() if p.exists() else None

    def save_manifest(self, signed_manifest_json: str) -> None:
        _write_atomic(self.dir / "manifest.json", signed_manifest_json.encode(), 0o644)

    # events ----------------------------------------------------------
    def events(self) -> Iterator[dict]:
        p = self.dir / "events.jsonl"
        if not p.exists():
            return
        with p.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        return  # partial last line after a crash

    def append_event(self, event: dict) -> None:
        with (self.dir / "events.jsonl").open("a") as f:
            f.write(json.dumps(event, separators=(",", ":")) + "\n")

    # blobs -----------------------------------------------------------
    def read_blob(self, item_id: str) -> Optional[bytes]:
        # Ids reach here from the relay; anything else could name another file.
        if not _ITEM_ID.fullmatch(item_id):
            return None
        p = self.dir / "blobs" / item_id
        return p.read_bytes() if p.exists() else None

    def write_blob(self, item_id: str, blob: bytes) -> None:
        if not _ITEM_ID.fullmatch(item_id):
            raise ValueError(f"not an item id: {item_id!r}")
        _write_atomic(self.dir / "blobs" / item_id, blob)

    def delete(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    @staticmethod
    def sweep_expired(root: Path) -> None:
        """Delete caches of sessions whose manifest has expired."""
        now = int(time.time() * 1000)
        if not Path(root).exists():
            return
        for d in Path(root).iterdir():
            # Only session caches, never another directory with a manifest.json.
            if not _SESSION_ID.fullmatch(d.name):
                continue
            m = d / "manifest.json"
            try:
                expires = json.loads(m.read_text())["manifest"]["expires_at_ms"]
            except (OSError, ValueError, KeyError):
                continue
            if expires <= now:
                shutil.rmtree(d, ignore_errors=True)
