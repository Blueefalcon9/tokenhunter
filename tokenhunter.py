#!/usr/bin/env python3
"""
token-finder
Author: Your Name
Description: Find secrets/tokens in files or git history with regex + entropy.
"""

import argparse, base64, binascii, json, csv, os, re, subprocess, sys
from pathlib import Path
from math import log2
from typing import List, Dict, Any
from tqdm import tqdm
from rich.console import Console
from rich.table import Table

console = Console()

DEFAULT_INCLUDE_EXT = {
    ".txt",".conf",".cfg",".ini",".env",".json",".yml",".yaml",".xml",
    ".py",".js",".ts",".tsx",".jsx",".go",".rb",".php",".java",".cs",
    ".ps1",".sh",".bash",".zsh",".pl",".rs",".swift",".tf",".hcl",".sql",
    ".md",".html",".css",".properties",".gradle",".dockerfile",".gitmodules"
}
DEFAULT_EXCLUDE_DIRS = {".git",".idea",".vscode","node_modules","dist","build","__pycache__",".venv","venv"}

# --- Patterns (curated & portfolio-safe) ---
PATTERNS = {
    "AWS Access Key ID": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "AWS Secret Key": re.compile(r"\b(?<![A-Za-z0-9+/=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9+/=])\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "Slack Token": re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,48})\b"),
    "GitHub Token/PAT": re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b"),
    "Bearer Token": re.compile(r"\bBearer\s+([A-Za-z0-9\-\._~\+\/]+=*)\b"),
    "Generic API Key": re.compile(r"\b(api|secret|token|key|passwd|password)[\s:=]+([\"']?[A-Za-z0-9_\-]{16,}[^ \n\"']*)", re.I),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
}

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    alphabet = {c for c in s}
    return -sum((s.count(c)/len(s))*log2(s.count(c)/len(s)) for c in alphabet)

def looks_binary(chunk: bytes) -> bool:
    # Heuristic: if it has nulls or a high ratio of non-text bytes
    if b"\x00" in chunk: return True
    textish = sum(1 for b in chunk if 9 <= b <= 13 or 32 <= b <= 126)
    return textish / max(len(chunk),1) < 0.85

def mask_secret(s: str, visible: int = 4) -> str:
    if len(s) <= visible: return "*" * len(s)
    return "*" * (len(s)-visible) + s[-visible:]

def read_text_safely(path: Path, max_bytes: int) -> str:
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
            if looks_binary(data):
                return ""
            # try utf-8 then fallback latin-1
            try:
                return data.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                return data.decode("latin-1", errors="ignore")
    except Exception:
        return ""

def iter_files(root: Path, include_ext: set, exclude_dirs: set, max_size: int):
    for p in root.rglob("*"):
        try:
            if p.is_dir():
                if p.name in exclude_dirs:
                    # skip subtree
                    for _ in p.rglob("*"):  # cheap way to advance generator
                        pass
                continue
            if p.suffix.lower() not in include_ext and p.suffix:
                continue
            if p.is_file():
                size = p.stat().st_size
                if size <= max_size:
                    yield p
        except Exception:
            continue

def scan_text(text: str, rel: str, entropy_threshold: float, max_len: int):
    findings = []
    for name, rx in PATTERNS.items():
        for m in rx.finditer(text):
            val = m.group(0)
            if len(val) > max_len:  # avoid absurd captures
                continue
            # special case for Generic API Key capture group
            if name == "Generic API Key" and m.lastindex and m.lastindex >= 2:
                val = m.group(2)
            ent = shannon_entropy(val)
            findings.append({
                "source": rel,
                "type": name,
                "secret": val,
                "entropy": round(ent, 3)
            })
    # entropy sweep for base64ish or long tokens
    for token in re.findall(r"[A-Za-z0-9_\-]{20,}", text):
        if len(token) <= max_len and shannon_entropy(token) >= entropy_threshold:
            findings.append({
                "source": rel,
                "type": "High-Entropy",
                "secret": token,
                "entropy": round(shannon_entropy(token), 3)
            })
    return findings

def scan_git(root: Path, entropy_threshold: float, max_len: int):
    findings = []
    try:
        subprocess.run(["git","rev-parse","--is-inside-work-tree"], cwd=root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        console.print("[yellow]--git set, but not a git repo. Skipping history.[/yellow]")
        return findings

    try:
        proc = subprocess.Popen(["git","log","-p","-U0","--pretty=format:commit:%H"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        buf = []
        for line in proc.stdout:
            if line.startswith("commit:"):
                # flush previous patch
                if buf:
                    text = "".join(buf)
                    findings.extend(scan_text(text, rel="GIT_HISTORY", entropy_threshold=entropy_threshold, max_len=max_len))
                    buf = []
            else:
                # only look at added lines to reduce noise
                if line.startswith("+") and not line.startswith("+++"):
                    buf.append(line[1:])
        if buf:
            text = "".join(buf)
            findings.extend(scan_text(text, rel="GIT_HISTORY", entropy_threshold=entropy_threshold, max_len=max_len))
    except Exception as e:
        console.print(f"[red]git history scan error: {e}[/red]")
    return findings

def main():
    ap = argparse.ArgumentParser(description="token-finder — scan secrets in files or git history")
    ap.add_argument("path", help="Path to folder or repo")
    ap.add_argument("-o","--output", default="output", help="Output directory")
    ap.add_argument("--include-ext", help="Comma list of extensions to include")
    ap.add_argument("--exclude-dirs", help="Comma list of directory names to skip")
    ap.add_argument("--max-size", type=int, default=2_000_000, help="Max file size to read (bytes)")
    ap.add_argument("--max-capture", type=int, default=512, help="Max length of a captured token")
    ap.add_argument("--entropy", type=float, default=4.0, help="Shannon entropy threshold for generic tokens")
    ap.add_argument("--git", action="store_true", help="Also scan git history (added lines)")
    args = ap.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
