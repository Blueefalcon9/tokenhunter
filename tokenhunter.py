#!/usr/bin/env python3
"""
tokenhunter - find leaked credentials in files and git history.

Designed for assessment work: findings are masked by default, carry a stable
fingerprint so they can be baselined, and exit codes make it usable in CI.

Authorized use only. Scan code you own or have written permission to review.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Iterator, Optional

try:
    from rich.console import Console
    from rich.table import Table
    _console: Optional["Console"] = Console(stderr=True)
except ImportError:  # rich is optional - degrade to plain text
    _console = None

VERSION = "2.0.0"

SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}

# --------------------------------------------------------------------------
# Filesystem traversal
# --------------------------------------------------------------------------

DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".vscode", "node_modules", "bower_components",
    "vendor", "dist", "build", "target", "out", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".tox", ".venv", "venv", "env", ".next",
    ".nuxt", ".gradle", ".terraform", "site-packages", ".cargo", "Pods",
}

# Extensions that are archives/media/binaries - never worth reading as text.
SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg", ".tif", ".tiff",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".flac", ".ogg", ".webm",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".ear",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt",
    ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a", ".class", ".pyc", ".pyo",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".wasm", ".pack", ".idx",
}

# Filenames that are themselves worth flagging if present.
SENSITIVE_NAMES = {
    "id_rsa": ("Private key file", "critical"),
    "id_dsa": ("Private key file", "critical"),
    "id_ecdsa": ("Private key file", "critical"),
    "id_ed25519": ("Private key file", "critical"),
    ".netrc": ("netrc credentials file", "high"),
    ".pgpass": ("PostgreSQL password file", "high"),
    "credentials": ("Cloud credentials file", "high"),
    ".htpasswd": ("htpasswd file", "medium"),
    "shadow": ("Password hash file", "critical"),
}

# Lockfiles and minified assets: huge, high-entropy, never hold real secrets.
NOISE_FILE_RX = re.compile(
    r"(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Cargo\.lock|"
    r"Gemfile\.lock|composer\.lock|go\.sum|\.min\.(js|css)|\.map)$"
)


def iter_files(root: Path, exclude_dirs: set[str], include_ext: Optional[set[str]],
               max_size: int, follow_symlinks: bool = False) -> Iterator[Path]:
    """Walk root, pruning excluded directories.

    Uses os.walk so that excluded directories are genuinely pruned from the
    traversal rather than filtered after the fact.
    """
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        # Prune in place - this is what stops os.walk descending.
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs and not d.startswith(".git")]
        for fn in filenames:
            p = Path(dirpath) / fn
            ext = p.suffix.lower()
            if ext in SKIP_EXT:
                continue
            if include_ext is not None and ext not in include_ext:
                continue
            if NOISE_FILE_RX.search(fn):
                continue
            try:
                if not follow_symlinks and p.is_symlink():
                    continue
                if p.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            yield p


def looks_binary(chunk: bytes) -> bool:
    if b"\x00" in chunk:
        return True
    if not chunk:
        return False
    textish = sum(1 for b in chunk if 9 <= b <= 13 or 32 <= b <= 126)
    return textish / len(chunk) < 0.85


def read_text(path: Path, max_bytes: int) -> str:
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
    except OSError:
        return ""
    if looks_binary(data):
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


# --------------------------------------------------------------------------
# Entropy
# --------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char. O(n) via Counter."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


HEX_RX = re.compile(r"\A[0-9a-f]+\Z", re.I)
_UUID_RX = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z", re.I)


def is_probably_not_secret(val: str) -> bool:
    """Filter the classic false positives before entropy is even considered."""
    if _UUID_RX.match(val):
        return True
    # Git object IDs / checksums: pure hex of a known digest length.
    if HEX_RX.match(val) and len(val) in (32, 40, 56, 64, 96, 128):
        return True
    # Repeated or sequential filler.
    if len(set(val)) <= 4:
        return True
    return False


# --------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------

@dataclass
class Detector:
    name: str
    regex: re.Pattern
    severity: str = "high"
    group: int = 0
    # Optional extra validation on the captured value.
    validator: Optional[Callable[[str], bool]] = None
    # If set, the match only counts when this appears within `window` chars.
    context: Optional[re.Pattern] = None
    window: int = 80
    # True for structurally unmistakable credentials (AKIA..., ghp_..., sk_live_...).
    # These skip the placeholder/noise filters: the prefix alone is proof enough,
    # and a vendor prefix plus 36 random chars can legitimately contain a substring
    # like "123456" or "example" that would otherwise suppress a real finding.
    precise: bool = False


def _luhn_free_b64(v: str) -> bool:
    return not is_probably_not_secret(v)


def _aws_secret_ok(v: str) -> bool:
    """A 40-char base64 blob is only interesting with real variety.

    Rejects pure hex (git SHAs), UUIDs, and anything with too narrow an
    alphabet. Still requires AWS context via the detector's `context`.
    """
    if is_probably_not_secret(v):
        return False
    classes = sum([
        bool(re.search(r"[a-z]", v)),
        bool(re.search(r"[A-Z]", v)),
        bool(re.search(r"[0-9]", v)),
        bool(re.search(r"[/+]", v)),
    ])
    return classes >= 3


def _jwt_ok(v: str) -> bool:
    """Decode the JWT header and confirm it really is one."""
    import base64
    head = v.split(".", 1)[0]
    try:
        pad = "=" * (-len(head) % 4)
        obj = json.loads(base64.urlsafe_b64decode(head + pad))
    except Exception:
        return False
    return isinstance(obj, dict) and "alg" in obj


DETECTORS: list[Detector] = [
    # --- cloud -------------------------------------------------------------
    Detector("AWS Access Key ID",
             re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
             "critical", group=1, precise=True),
    Detector("AWS Secret Access Key",
             re.compile(r"\b([A-Za-z0-9/+=]{40})\b"), "critical", group=1,
             validator=_aws_secret_ok,
             context=re.compile(r"aws|secret[_-]?access|s3", re.I)),
    Detector("Google API Key",
             re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
             "high", group=1, precise=True),
    Detector("GCP Service Account",
             re.compile(r'"type"\s*:\s*"service_account"'),
             "critical", precise=True),
    Detector("Azure Storage Key",
             re.compile(r"\b(DefaultEndpointsProtocol=https?;[^\s\"']*AccountKey=[A-Za-z0-9/+=]{40,})"),
             "critical", group=1, precise=True),
    Detector("Azure AD Client Secret",
             re.compile(r"\b([A-Za-z0-9~._\-]{34,40})\b"), "high", group=1,
             validator=_luhn_free_b64,
             context=re.compile(r"client[_-]?secret|azure|tenant[_-]?id", re.I)),

    # --- vcs / registries --------------------------------------------------
    Detector("GitHub Token",
             re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b"),
             "critical", group=1, precise=True),
    Detector("GitHub Fine-Grained PAT",
             re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,})\b"),
             "critical", group=1, precise=True),
    Detector("GitLab Token",
             re.compile(r"\b(glpat-[A-Za-z0-9\-_]{20,})\b"),
             "critical", group=1, precise=True),
    Detector("npm Token",
             re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
             "high", group=1, precise=True),
    Detector("PyPI Token",
             re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,})\b"),
             "high", group=1, precise=True),

    # --- saas --------------------------------------------------------------
    Detector("Slack Token",
             re.compile(r"\b(xox[baprse]-[0-9A-Za-z\-]{10,64})\b"),
             "critical", group=1, precise=True),
    Detector("Slack Webhook",
             re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_/]{20,})"),
             "high", group=1, precise=True),
    Detector("Stripe Secret Key",
             re.compile(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,})\b"),
             "critical", group=1, precise=True),
    Detector("SendGrid Key",
             re.compile(r"\b(SG\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,})\b"),
             "high", group=1, precise=True),
    Detector("Twilio Key",
             re.compile(r"\b(SK[0-9a-fA-F]{32})\b"),
             "high", group=1, precise=True),
    Detector("OpenAI Key",
             re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9\-_]{20,})\b"),
             "high", group=1, precise=True),
    Detector("Anthropic Key",
             re.compile(r"\b(sk-ant-[A-Za-z0-9\-_]{20,})\b"),
             "high", group=1, precise=True),

    # --- generic -----------------------------------------------------------
    Detector("Private Key Block",
             re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
             "critical", precise=True),
    Detector("JWT",
             re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"),
             "medium", group=1, validator=_jwt_ok, precise=True),
    Detector("DB Connection String",
             re.compile(r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://"
                        r"[^:\s/@]+:[^@\s/]{3,}@[^\s/\"'<>]+)"),
             "critical", group=1, precise=True),
    Detector("Basic Auth URL",
             re.compile(r"\b(https?://[^:\s/@]+:[^@\s/]{3,}@[^\s/\"'<>]+)"),
             "high", group=1, precise=True),
    Detector("Authorization Header",
             re.compile(r"[Aa]uthorization\s*[:=]\s*[\"']?(?:Bearer|Basic|Token)\s+([A-Za-z0-9\-._~+/]{16,}=*)"),
             "high", group=1),
    # Assignment-shaped generic secret. Requires a quoted value to cut noise.
    Detector("Hardcoded Secret Assignment",
             re.compile(r"(?:api[_-]?key|apikey|secret|token|passwd|password|passphrase|"
                        r"auth[_-]?token|access[_-]?key|private[_-]?key)"
                        r"\s*[:=]\s*[\"']([^\"'\s]{12,120})[\"']", re.I),
             "medium", group=1, validator=_luhn_free_b64),
]

# Values that are obviously placeholders, not credentials.
PLACEHOLDER_RX = re.compile(
    r"\A(?:"
    r"x{3,}|y{3,}|z{3,}|\.{3,}|-+|_+|\*+|"
    r"(?:your|my|the|a)[_-]?(?:api|key|secret|token|password|pass).*|"
    r".*(?:example|sample|placeholder|changeme|change[_-]?me|dummy|fake|test[_-]?key|"
    r"redacted|insert|todo|fixme|none|null|nil|undefined|empty|default|"
    r"xxxxx|123456|password|secret|abc123|foobar)\w*"
    r")\Z", re.I
)


def is_placeholder(val: str) -> bool:
    return bool(PLACEHOLDER_RX.match(val.strip()))


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------

@dataclass
class Finding:
    detector: str
    severity: str
    path: str
    line: int
    secret: str = field(repr=False)
    entropy: float = 0.0
    commit: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None
    context: str = ""

    @property
    def fingerprint(self) -> str:
        """Stable id for baselining. Ignores line number so edits don't churn it."""
        h = hashlib.sha256()
        h.update(f"{self.detector}|{self.path}|{self.secret}".encode())
        return h.hexdigest()[:16]

    def masked(self, visible: int = 4) -> str:
        s = self.secret
        if len(s) <= visible:
            return "*" * len(s)
        return "*" * min(len(s) - visible, 24) + s[-visible:]

    def to_row(self, unmask: bool) -> dict:
        d = asdict(self)
        d["secret"] = self.secret if unmask else self.masked()
        d["fingerprint"] = self.fingerprint
        return d


def scan_text(text: str, path: str, *, entropy_threshold: float, max_capture: int,
              commit: Optional[str] = None, author: Optional[str] = None,
              date: Optional[str] = None, do_entropy: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    # Precompute line start offsets so we can map an index to a line number.
    line_starts = [0]
    for m in re.finditer(r"\n", text):
        line_starts.append(m.end())

    def line_of(idx: int) -> int:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= idx:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    seen: set[tuple[str, str]] = set()
    claimed: set[str] = set()

    for det in DETECTORS:
        for m in det.regex.finditer(text):
            try:
                val = m.group(det.group)
            except (IndexError, re.error):
                val = m.group(0)
            if not val or len(val) > max_capture:
                continue
            # Structural detectors trust their prefix; everything else gets the
            # placeholder screen.
            if not det.precise and is_placeholder(val):
                continue
            if det.validator and not det.validator(val):
                continue
            if det.context:
                lo = max(0, m.start() - det.window)
                if not det.context.search(text[lo:m.end() + det.window]):
                    continue
            # Cross-detector dedup: DETECTORS is ordered specific -> generic, so
            # the first (most specific) detector to claim a value keeps it. This
            # stops a GitHub token also being reported as a generic Azure secret.
            if val in claimed:
                continue
            claimed.add(val)
            key = (det.name, val)
            if key in seen:
                continue
            seen.add(key)
            ln = line_of(m.start())
            raw_line = text[line_starts[ln - 1]:].split("\n", 1)[0]
            findings.append(Finding(
                detector=det.name, severity=det.severity, path=path, line=ln,
                secret=val, entropy=round(shannon_entropy(val), 3),
                commit=commit, author=author, date=date,
                context=raw_line.strip()[:160],
            ))

    if do_entropy:
        for m in re.finditer(r"[A-Za-z0-9+/=_\-]{24,}", text):
            val = m.group(0)
            if len(val) > max_capture:
                continue
            if val in claimed:
                continue
            if is_probably_not_secret(val) or is_placeholder(val):
                continue
            ent = shannon_entropy(val)
            if ent < entropy_threshold:
                continue
            claimed.add(val)
            ln = line_of(m.start())
            raw_line = text[line_starts[ln - 1]:].split("\n", 1)[0]
            findings.append(Finding(
                detector="High Entropy String", severity="low", path=path, line=ln,
                secret=val, entropy=round(ent, 3),
                commit=commit, author=author, date=date,
                context=raw_line.strip()[:160],
            ))
    return findings


# --------------------------------------------------------------------------
# Git history
# --------------------------------------------------------------------------

def is_git_repo(root: Path) -> bool:
    try:
        subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=root,
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def scan_git_history(root: Path, *, entropy_threshold: float, max_capture: int,
                     do_entropy: bool, max_commits: Optional[int] = None) -> list[Finding]:
    """Scan added lines across history, attributing each finding to its commit."""
    findings: list[Finding] = []
    sep = "\x1fTH\x1f"  # unit separator: safe in argv, absent from commit metadata
    cmd = ["git", "log", "-p", "-U0", "--no-color", "--no-merges",
           f"--pretty=format:{sep}%H{sep}%an <%ae>{sep}%aI{sep}"]
    if max_commits:
        cmd.insert(2, f"-n{max_commits}")
    try:
        proc = subprocess.Popen(cmd, cwd=root, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, errors="replace")
    except FileNotFoundError:
        return findings

    commit = author = date = None
    cur_file = "GIT_HISTORY"
    buf: list[str] = []

    def flush():
        if not buf or not commit:
            return
        findings.extend(scan_text(
            "".join(buf), f"{cur_file}@{commit[:8]}",
            entropy_threshold=entropy_threshold, max_capture=max_capture,
            commit=commit, author=author, date=date, do_entropy=do_entropy))
        buf.clear()

    assert proc.stdout is not None
    for line in proc.stdout:
        if line.startswith(sep):
            flush()
            # rstrip("\r\n") only: str.strip() counts \x1c-\x1f as whitespace and
            # would eat the leading separator, breaking the field split.
            parts = line.rstrip("\r\n").split(sep)
            if len(parts) >= 4:
                commit, author, date = parts[1], parts[2], parts[3]
            continue
        if line.startswith("+++ b/"):
            flush()
            cur_file = line[6:].strip()
        elif line.startswith("+") and not line.startswith("+++"):
            buf.append(line[1:])
    flush()
    proc.wait()
    return findings


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def log(msg: str, style: str = "") -> None:
    if _console:
        _console.print(f"[{style}]{msg}[/{style}]" if style else msg)
    else:
        print(msg, file=sys.stderr)


def write_outputs(findings: list[Finding], outdir: Path, unmask: bool) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    rows = [f.to_row(unmask) for f in findings]

    (outdir / "findings.json").write_text(json.dumps(
        {"tool": "tokenhunter", "version": VERSION, "count": len(rows), "findings": rows},
        indent=2))

    cols = ["fingerprint", "severity", "detector", "path", "line", "secret",
            "entropy", "commit", "author", "date", "context"]
    with (outdir / "findings.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    # SARIF, so this can feed GitHub code scanning.
    rules, results = {}, []
    for f in findings:
        rules.setdefault(f.detector, {
            "id": f.detector.replace(" ", "_"),
            "name": f.detector,
            "shortDescription": {"text": f.detector},
            "defaultConfiguration": {
                "level": {"critical": "error", "high": "error",
                          "medium": "warning", "low": "note"}[f.severity]},
        })
        results.append({
            "ruleId": f.detector.replace(" ", "_"),
            "level": {"critical": "error", "high": "error",
                      "medium": "warning", "low": "note"}[f.severity],
            "message": {"text": f"{f.detector} ({f.severity}) - {f.masked()}"},
            "partialFingerprints": {"tokenhunter/v1": f.fingerprint},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.path},
                "region": {"startLine": max(1, f.line)},
            }}],
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "tokenhunter", "version": VERSION,
                                "informationUri": "https://github.com/Blueefalcon9/tokenhunter",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }
    (outdir / "findings.sarif").write_text(json.dumps(sarif, indent=2))


def print_table(findings: list[Finding], unmask: bool, limit: int = 60) -> None:
    if not findings:
        log("No findings.", "green")
        return
    if _console is None:
        for f in findings[:limit]:
            print(f"{f.severity:8} {f.detector:28} {f.path}:{f.line} {f.masked()}")
        return
    colour = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}
    t = Table(title=f"tokenhunter - {len(findings)} finding(s)")
    t.add_column("Sev", style="bold")
    t.add_column("Detector", style="cyan", max_width=26)
    t.add_column("Location", style="magenta", max_width=46, overflow="fold")
    t.add_column("Value", style="yellow", max_width=30, overflow="fold")
    t.add_column("H", justify="right", style="dim")
    for f in findings[:limit]:
        t.add_row(f"[{colour[f.severity]}]{f.severity}[/]", f.detector,
                  f"{f.path}:{f.line}", f.secret if unmask else f.masked(),
                  f"{f.entropy:.1f}")
    _console.print(t)
    if len(findings) > limit:
        log(f"... and {len(findings) - limit} more (see the JSON/CSV output)", "dim")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        prog="tokenhunter",
        description="Find leaked credentials in files and git history.",
        epilog="Authorized use only. Scan code you own or have permission to review.",
    )
    ap.add_argument("path", help="Folder or git repository to scan")
    ap.add_argument("-o", "--output", default="output", help="Output directory (default: output)")
    ap.add_argument("--git", action="store_true", help="Also scan git history (added lines)")
    ap.add_argument("--git-only", action="store_true", help="Scan only history, not the worktree")
    ap.add_argument("--max-commits", type=int, help="Limit history scan to N most recent commits")
    ap.add_argument("--include-ext", help="Comma list of extensions to include (default: all text)")
    ap.add_argument("--exclude-dirs", help="Comma list of extra directory names to skip")
    ap.add_argument("--max-size", type=int, default=2_000_000, help="Max file size in bytes (default: 2000000)")
    ap.add_argument("--max-capture", type=int, default=512, help="Max captured token length (default: 512)")
    ap.add_argument("--entropy", type=float, default=4.5,
                    help="Entropy threshold for the generic sweep (default: 4.5)")
    ap.add_argument("--no-entropy", action="store_true",
                    help="Disable the generic high-entropy sweep (named detectors only)")
    ap.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low",
                    help="Hide findings below this severity (default: low)")
    ap.add_argument("--baseline", help="JSON file of fingerprints to suppress")
    ap.add_argument("--write-baseline", action="store_true",
                    help="Write current findings to the --baseline path and exit 0")
    ap.add_argument("--unmask", action="store_true",
                    help="Show full secret values (default: masked to last 4 chars)")
    ap.add_argument("--fail-on", choices=list(SEVERITY_ORDER),
                    help="Exit 1 if any finding is at or above this severity")
    ap.add_argument("--quiet", action="store_true", help="Suppress the console table")
    ap.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks while walking")
    ap.add_argument("--version", action="version", version=f"tokenhunter {VERSION}")
    args = ap.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        log(f"Path does not exist: {root}", "bold red")
        return 2
    if not root.is_dir():
        log(f"Path is not a directory: {root}", "bold red")
        return 2

    exclude = set(DEFAULT_EXCLUDE_DIRS)
    if args.exclude_dirs:
        exclude |= {d.strip() for d in args.exclude_dirs.split(",") if d.strip()}
    include_ext = None
    if args.include_ext:
        include_ext = {("." + e.strip().lstrip(".")).lower()
                       for e in args.include_ext.split(",") if e.strip()}

    findings: list[Finding] = []
    do_entropy = not args.no_entropy

    # --- worktree ----------------------------------------------------------
    if not args.git_only:
        files = list(iter_files(root, exclude, include_ext, args.max_size,
                                args.follow_symlinks))
        log(f"Scanning {len(files)} file(s) under {root}", "cyan")
        for p in files:
            rel = str(p.relative_to(root))
            if p.name in SENSITIVE_NAMES:
                label, sev = SENSITIVE_NAMES[p.name]
                findings.append(Finding(detector=label, severity=sev, path=rel,
                                        line=1, secret=p.name, context="(file present)"))
            text = read_text(p, args.max_size)
            if text:
                findings.extend(scan_text(
                    text, rel, entropy_threshold=args.entropy,
                    max_capture=args.max_capture, do_entropy=do_entropy))

    # --- history -----------------------------------------------------------
    if args.git or args.git_only:
        if not is_git_repo(root):
            log("--git requested but this is not a git repository; skipping history.", "yellow")
        else:
            log("Scanning git history (added lines)...", "cyan")
            findings.extend(scan_git_history(
                root, entropy_threshold=args.entropy, max_capture=args.max_capture,
                do_entropy=do_entropy, max_commits=args.max_commits))

    # --- baseline ----------------------------------------------------------
    if args.baseline and not args.write_baseline:
        try:
            data = json.loads(Path(args.baseline).read_text())
            suppressed = set(data.get("fingerprints", []))
            before = len(findings)
            findings = [f for f in findings if f.fingerprint not in suppressed]
            log(f"Baseline suppressed {before - len(findings)} finding(s)", "dim")
        except (OSError, json.JSONDecodeError) as e:
            log(f"Could not read baseline: {e}", "yellow")

    # --- filter + sort -----------------------------------------------------
    floor = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in findings if SEVERITY_ORDER[f.severity] >= floor]
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.path, f.line))

    if args.write_baseline:
        target = Path(args.baseline or "tokenhunter-baseline.json")
        target.write_text(json.dumps(
            {"tool": "tokenhunter", "version": VERSION,
             "fingerprints": sorted({f.fingerprint for f in findings})}, indent=2))
        log(f"Wrote baseline with {len(findings)} fingerprint(s) to {target}", "green")
        return 0

    if not args.quiet:
        print_table(findings, args.unmask)

    outdir = Path(args.output)
    write_outputs(findings, outdir, args.unmask)
    log(f"Wrote findings.json, findings.csv and findings.sarif to {outdir}/", "blue")

    by_sev = Counter(f.severity for f in findings)
    log("  ".join(f"{k}={by_sev.get(k, 0)}" for k in
                  ("critical", "high", "medium", "low")), "bold")

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("\nInterrupted.", "yellow")
        sys.exit(130)
