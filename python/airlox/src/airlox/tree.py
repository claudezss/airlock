"""Working trees: a checkout as one job input, as ``airlox run --tree`` sends it.

The file list is what git would commit plus what it would add (``git
ls-files -co --exclude-standard``: tracked and untracked files, ignored ones
left out), from the repository root, zipped as ``tree.zip`` with
``.airlox/tree.json`` describing it. Outside a repository it is every
regular file under the directory except ``.git``.

Untracked files are the usual home of secrets, so a tree holding a file with
a well-known credential name is refused unless ``allow`` names it;
``exclude`` and ``.airloxignore`` drop files. The list is a seat belt, not a
scanner.

To a runner that keeps the sender's workspace, a tree can go as a *delta*
(:meth:`Tree.delta`): ``tree.json`` still lists every file, but the zip holds
only those that differ from what the sender last left there. The runner
checks the rest on disk and refuses the job (``tree_stale``) if any is not
as listed; the sender then sends the whole tree.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Union

from . import _core as ac

#: The input's file name; a runner knows a tree by the job's ``tree`` field.
TREE_ZIP = "tree.zip"
#: Where the description goes inside the zip.
TREE_JSON = ".airlox/tree.json"
#: Read from the tree's root: one glob per line, like ``exclude``.
IGNORE_FILE = ".airloxignore"

#: File names that usually hold credentials (matched against the name, not
#: the path, ignoring case).
CREDENTIAL_NAMES = (
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.keystore", "*.jks", "id_rsa*", "id_dsa*",
    "id_ecdsa*", "id_ed25519*", ".netrc", "_netrc", ".npmrc", ".pypirc", ".pgpass", ".git-credentials",
    "credentials", "credentials.json", "*.tfstate", "*.tfstate.*", "*.tfvars", "kubeconfig",
)
#: Paths that hold credentials although their names are common: the end of
#: the path, ignoring case.
CREDENTIAL_PATHS = (".docker/config.json", ".kube/config")

#: A job input holds at most this many entries (tree.json is one of them).
_MAX_ENTRIES = 10_000
# A fixed timestamp, so the same files make the same zip.
_EPOCH = (1980, 1, 1, 0, 0, 0)


class TreeRefused(ValueError):
    """The tree cannot be sent as it is: it holds files named like
    credentials, or more files than a job input may hold."""


def glob_match(pattern: str, text: str) -> bool:
    """Shell-style glob over a ``/``-separated path: ``*`` and ``?`` stay
    within a component, ``**`` crosses them."""

    def rec(p: str, t: str) -> bool:
        if not p:
            return not t
        if p.startswith("**"):
            rest = p[2:]
            rest = rest[1:] if rest.startswith("/") else rest
            return any(rec(rest, t[i:]) for i in range(len(t) + 1))
        if p[0] == "*":
            for i in range(len(t) + 1):
                if i > 0 and t[i - 1] == "/":
                    break
                if rec(p[1:], t[i:]):
                    return True
            return False
        if p[0] == "?":
            return bool(t) and t[0] != "/" and rec(p[1:], t[1:])
        return bool(t) and t[0] == p[0] and rec(p[1:], t[1:])

    return rec(pattern, text)


def pattern_matches(pattern: str, path: str) -> bool:
    """Whether a pattern names this path: one with a ``/`` matches the whole
    path (or a directory above it); one without matches any component, as
    in ``.gitignore``."""
    pattern = pattern.strip()
    while pattern.startswith("./"):
        pattern = pattern[2:]
    pattern = pattern[:-1] if pattern.endswith("/") else pattern
    if not pattern:
        return False
    if pattern.startswith("/"):
        anchored = pattern[1:]
        return glob_match(anchored, path) or glob_match(anchored + "/**", path)
    if "/" in pattern:
        return glob_match(pattern, path) or glob_match(pattern + "/**", path)
    return any(glob_match(pattern, c) for c in path.split("/"))


def _credential_name(path: str) -> bool:
    path = path.lower()
    name = path.rsplit("/", 1)[-1]
    return any(glob_match(p, name) for p in CREDENTIAL_NAMES) or any(
        path == p or path.endswith("/" + p) for p in CREDENTIAL_PATHS
    )


def _git(root: Path, *args: str) -> Optional[str]:
    try:
        out = subprocess.run(["git", "-C", str(root), *args], capture_output=True)
    except OSError:
        return None
    return out.stdout.decode("utf-8", "replace") if out.returncode == 0 else None


def _walk(root: Path, notes: List[str]) -> List[str]:
    out = []
    for d, dirs, files in os.walk(root):
        rel = Path(d).relative_to(root).as_posix()
        keep = []
        for x in dirs:
            p = x if rel == "." else f"{rel}/{x}"
            if x == ".git":
                continue
            if (Path(d) / x).is_symlink():
                notes.append(f"left out {p}: a symbolic link")
                continue
            keep.append(x)
        dirs[:] = keep
        for f in files:
            out.append(f if rel == "." else f"{rel}/{f}")
    return sorted(out)


def _human(n: int) -> str:
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


@dataclass
class Tree:
    #: The repository root (or the directory, outside a repository).
    root: Path
    #: ``.airlox/tree.json``: ``root_name``, ``head``, ``branch``, ``dirty``,
    #: ``files`` [{path, sha256, mode}], ``count``, ``bytes``.
    json: dict
    zip: bytes
    #: The directory the tree was built from, relative to the root
    #: (``/``-separated); ``None`` at the root. Jobs start there.
    cwd: Optional[str]
    in_git: bool
    #: Files changed against ``head`` (from ``git status``).
    changed: Optional[int] = None
    #: Up to five of the largest files, largest first: (path, bytes).
    largest: List[Tuple[str, int]] = field(default_factory=list)
    #: Files left out, and why.
    notes: List[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return self.json["count"]

    def summary(self) -> str:
        """``"tree 412 files, 3.1 MB (18 changed)"``."""
        changed = {None: "", 0: " (clean)"}.get(self.changed, f" ({self.changed} changed)")
        return f"tree {self.count} files, {_human(self.json['bytes'])}{changed}"

    def listing(self) -> Dict[str, str]:
        """Path to hex SHA-256 of every file in the tree."""
        return {f["path"]: f["sha256"] for f in self.json["files"]}

    def delta(self, held: Dict[str, str]) -> Optional[Tuple[bytes, int]]:
        """The tree as a delta against ``held`` (path to hex SHA-256 of what
        the workspace should hold): a zip of the files that differ, and how
        many that is. ``None`` when nothing would be left out."""
        send = [f for f in self.json["files"] if held.get(f["path"]) != f["sha256"]]
        if len(send) == len(self.json["files"]):
            return None
        buf = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(self.zip)) as full, zipfile.ZipFile(buf, "w") as w:
            for f in send:
                info = full.getinfo(f["path"])
                w.writestr(info, full.read(info))
            w.writestr(_info(TREE_JSON, 0o100644), json.dumps({**self.json, "delta": True}))
        return buf.getvalue(), len(send)


def _info(name: str, mode: int) -> zipfile.ZipInfo:
    zi = zipfile.ZipInfo(name, date_time=_EPOCH)
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.create_system = 3  # unix, so the mode below is read
    zi.external_attr = (stat.S_IFREG | (mode & 0o777)) << 16
    return zi


def build(
    directory: Union[str, Path] = ".", *, allow: Iterable[str] = (), exclude: Iterable[str] = ()
) -> Tree:
    """The tree ``directory`` belongs to: its repository (or the directory
    itself, outside one). Raises ``TreeRefused`` if it holds files named
    like credentials that ``allow`` does not name (leave them out with
    ``exclude`` or a line in ``.airloxignore`` instead)."""
    directory = Path(directory).resolve()
    notes: List[str] = []
    top = _git(directory, "rev-parse", "--show-toplevel")
    in_git = bool(top and top.strip())
    root = Path(top.strip()).resolve() if in_git else directory
    # Outside a repository a tree is every file under the directory: not a
    # home directory's dotfiles, nor a whole disk.
    if not in_git and (root.parent == root or root == Path.home().resolve()):
        where = "the root of a disk" if root.parent == root else "your home directory"
        raise TreeRefused(f"{root} is {where}, not a project: build a tree from a project's directory")
    if in_git:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "-co", "--exclude-standard"], capture_output=True
        )
        if out.returncode != 0:
            raise RuntimeError(f"git ls-files failed: {out.stderr.decode('utf-8', 'replace').strip()}")
        listed = sorted({p.decode("utf-8", "replace") for p in out.stdout.split(b"\0") if p})
    else:
        listed = _walk(root, notes)
    allow = list(allow)
    excludes = list(exclude)
    try:
        text = (root / IGNORE_FILE).read_bytes().decode("utf-8", "replace")
        excludes += [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    except OSError:
        pass
    files, flagged = [], []
    for rel in listed:
        if any(pattern_matches(p, rel) for p in excludes):
            continue
        # The tree's own description lives there; runners refuse a tree
        # that has anything else in it.
        if rel.startswith(".airlox/"):
            notes.append(f"left out {rel}: .airlox/ is reserved for the tree's description")
            continue
        path = root / rel
        try:
            st = path.lstat()
        except OSError:
            continue  # a tracked file deleted in the work tree
        if stat.S_ISLNK(st.st_mode):
            notes.append(f"left out {rel}: a symbolic link")
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        try:
            ac.check_zip_path(rel)
        except ac.AirloxError:
            notes.append(f"left out {rel}: the name is not portable")
            continue
        if _credential_name(rel) and not any(pattern_matches(p, rel) for p in allow):
            flagged.append(rel)
            continue
        files.append((rel, path, 0o100755 if st.st_mode & 0o111 else 0o100644))
    if flagged:
        shown = flagged[:10]
        more = f" and {len(flagged) - len(shown)} more" if len(flagged) > len(shown) else ""
        raise TreeRefused(
            f"the tree holds files whose names usually mean credentials: {', '.join(shown)}{more}. "
            f"Leave them out with exclude=[...] (or a line in {IGNORE_FILE}), or send them anyway with allow=[...]"
        )
    if len(files) + 1 > _MAX_ENTRIES:
        raise TreeRefused(
            f"the tree has {len(files)} files; a job input holds at most {_MAX_ENTRIES - 1}. "
            "Leave some out with exclude=[...]"
        )
    buf = io.BytesIO()
    entries, sizes, total = [], [], 0
    with zipfile.ZipFile(buf, "w") as w:
        for rel, path, mode in files:
            data = path.read_bytes()
            w.writestr(_info(rel, mode), data)
            total += len(data)
            sizes.append((rel, len(data)))
            entries.append({"path": rel, "sha256": hashlib.sha256(data).hexdigest(), "mode": mode})
        head = branch = changed = None
        if in_git:
            head = (_git(root, "rev-parse", "--verify", "-q", "HEAD") or "").strip() or None
            branch = (_git(root, "symbolic-ref", "--short", "-q", "HEAD") or "").strip() or None
            status = _git(root, "status", "--porcelain")
            changed = None if status is None else len(status.splitlines())
        desc = {
            "root_name": root.name,
            "head": head,
            "branch": branch,
            "dirty": changed is None or changed > 0,
            "files": entries,
            "count": len(entries),
            "bytes": total,
        }
        w.writestr(_info(TREE_JSON, 0o100644), json.dumps(desc))
    data = buf.getvalue()
    ac.inspect_zip(data)
    cwd = None
    rel_dir = directory.relative_to(root).as_posix() if directory != root else "."
    if rel_dir != ".":
        try:
            ac.check_cwd(rel_dir)
        except ac.AirloxError as e:
            raise TreeRefused(f"{e}; build the tree from a directory a job can start in, such as the repository root") from None
        cwd = rel_dir
    sizes.sort(key=lambda s: (-s[1], s[0]))
    return Tree(root=root, json=desc, zip=data, cwd=cwd, in_git=in_git, changed=changed, largest=sizes[:5], notes=notes)
