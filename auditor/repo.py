"""Repository acquisition: validate the URL and make a disposable read-only clone."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

CLONE_TIMEOUT = 300
CLONE_DEPTH = 300

# Case-insensitive: domains are (GitHub.com == github.com), and GitHub owner/repo names are too.
_GITHUB_URL = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/"
    r"(?P<name>[A-Za-z0-9._-]{1,100}?)(?:\.git)?(?:/(?:tree|blob)/[^\s]*)?/?$",
    re.IGNORECASE,
)
# Inputs that are clearly meant as filesystem paths: ./x, ../x, /x, ~/x, \x, C:\x, C:/x, or any backslash.
_PATH_LIKE = re.compile(r"^(?:\.{1,2}[\\/]|[\\/~]|[A-Za-z]:[\\/])|\\")

# git error text (forced to English by _git_env) that means "the repo does not exist or is not public".
_NOT_FOUND_MARKERS = (
    "repository not found", "not found", "could not read username", "terminal prompts disabled",
    "authentication failed", "authentication required",
)


class RepoError(Exception):
    """The repository could not be validated or fetched."""


@dataclass
class RepoSource:
    display_url: str    # what goes in the report's "repository" field
    clone_url: str      # what git clones from


@dataclass
class Checkout:
    path: Path
    default_branch: str
    head_commit: str
    commit_count: int
    shallow: bool


def parse_repo(arg: str) -> RepoSource:
    """Accept a public GitHub URL (https://github.com/owner/repo[.git][/tree/...]) or a local git repo path."""
    if not arg or not arg.strip():
        raise RepoError("repository URL is empty")
    arg = arg.strip()
    local = Path(arg).expanduser()
    if local.is_dir():
        if not (local / ".git").exists():
            raise RepoError(f"local path '{arg}' is not a git repository")
        resolved = local.resolve()
        return RepoSource(display_url=str(resolved), clone_url=str(resolved))
    if local.exists():
        raise RepoError(f"local path '{arg}' is a file, not a git repository folder")
    if "://" not in arg and "github.com" not in arg.lower() and _PATH_LIKE.search(arg):
        raise RepoError(
            f"local path '{arg}' does not exist. Pass an existing git repository folder "
            "or a URL like https://github.com/<owner>/<repo>"
        )
    # Links copied from a browser often carry ?tab=readme-ov-file or #section: they don't change the repo.
    url_part = arg.split("#", 1)[0].split("?", 1)[0]
    m = _GITHUB_URL.match(url_part)
    if not m:
        raise RepoError(
            f"'{arg}' is not a GitHub repository URL. Expected https://github.com/<owner>/<repo>"
        )
    owner, name = m.group("owner"), m.group("name")
    if name in (".", ".."):
        raise RepoError(f"invalid repository name in '{arg}'")
    url = f"https://github.com/{owner}/{name}"
    return RepoSource(display_url=url, clone_url=url + ".git")


def _git_env() -> dict[str, str]:
    return {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",      # never block on a credential prompt (private/missing repo)
        "GCM_INTERACTIVE": "never",
        "GIT_LFS_SKIP_SMUDGE": "1",      # do not download LFS blobs
        "GIT_ASKPASS": "",
        # Force untranslated (English) git messages so error detection below works on any system language.
        "LC_ALL": "C",
        "LANG": "C",
        "LANGUAGE": "C",
    }


def _clone_error(exc: RepoError, display_url: str) -> RepoError:
    """Turn git's clone failure text into a friendly message where we recognise it."""
    msg = str(exc).lower()
    if any(marker in msg for marker in _NOT_FOUND_MARKERS):
        return RepoError(f"repository {display_url} not found or not public")
    return exc


def _run_git(args: list[str], cwd: Path | None = None, timeout: int = 60) -> str:
    try:
        proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, timeout=timeout, env=_git_env())
    except FileNotFoundError as exc:
        raise RepoError("git is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise RepoError(f"git {args[0]} timed out after {timeout}s") from exc
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise RepoError(f"git {args[0]} failed: {err[-600:]}")
    return proc.stdout.decode("utf-8", "replace").strip()


def clone(source: RepoSource, dest_parent: Path | None = None) -> Checkout:
    """Clone ``source`` into a fresh temporary directory. The source repository is never modified."""
    workdir = Path(tempfile.mkdtemp(prefix="devops-audit-", dir=dest_parent))
    dest = workdir / "repo"
    args = [
        "clone", "--quiet", "--single-branch", "--no-tags", f"--depth={CLONE_DEPTH}",
        "--config", "core.symlinks=false",
        "--config", "core.autocrlf=false",
        "--config", "core.longpaths=true",
        "--config", "core.hooksPath=" + os.devnull,
    ]
    if Path(source.clone_url).exists():
        args.insert(args.index("--quiet"), "--no-local")  # copy objects instead of hard-linking them
    args += [source.clone_url, str(dest)]
    try:
        _run_git(args, timeout=CLONE_TIMEOUT)
    except RepoError as exc:
        cleanup(workdir)
        friendly = _clone_error(exc, source.display_url)
        if friendly is exc:
            raise
        raise friendly from exc
    try:
        head = _run_git(["rev-parse", "HEAD"], cwd=dest)
        branch = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=dest)
        count = int(_run_git(["rev-list", "--count", "HEAD"], cwd=dest) or 0)
    except RepoError as exc:
        cleanup(workdir)
        if "ambiguous argument 'HEAD'" in str(exc) or "unknown revision" in str(exc):
            raise RepoError(f"repository {source.display_url} is empty (no commits)") from exc
        raise
    return Checkout(path=dest, default_branch=branch, head_commit=head, commit_count=count,
                    shallow=(dest / ".git" / "shallow").exists())


def _force_remove(func, path, _exc):  # git pack files are read-only on Windows
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def cleanup(path: Path) -> None:
    """Delete a temporary clone. Refuses anything that is not one of our temp dirs."""
    path = Path(path)
    root = path if path.name.startswith("devops-audit-") else path.parent
    if not root.name.startswith("devops-audit-"):
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(root, onexc=_force_remove)
    else:  # pragma: no cover - Python 3.10/3.11
        shutil.rmtree(root, onerror=_force_remove)
