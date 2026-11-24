# TokenHunter

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Find leaked credentials in a working tree or across git history. Findings are **masked by default**,
carry a **stable fingerprint** so they can be baselined, and drive an **exit code** so this works in CI.

## Why v2

v1 shipped truncated — the file ended mid-function and raised `IndentationError` on every run. v2 is
a complete rewrite. Alongside finishing it, these defects were fixed:

| Defect in v1 | Effect | Fix |
|---|---|---|
| `--exclude-dirs` never pruned anything | `node_modules` was fully scanned; the dominant noise source | `os.walk` with in-place `dirnames` pruning |
| AWS-secret regex matched any 40 base64 chars | **every git SHA-1 was a "finding"** | Requires AWS context + 3 character classes; hex digests rejected |
| Secrets stored raw despite the README | masking was documented but not implemented | Masked by default, `--unmask` to opt out |
| `shannon_entropy` was O(n²) | slow on large files | `Counter`, O(n) |
| Entropy swept every 20+ char token | enormous false-positive volume | Threshold raised to 4.5, UUID/hex/placeholder screens, `--no-entropy` |
| Git history lost commit identity | you knew a secret leaked, not where from | Per-commit attribution: hash, author, date |

## Detectors

24 named detectors across cloud (AWS, GCP, Azure), VCS/registries (GitHub, GitLab, npm, PyPI), SaaS
(Slack, Stripe, SendGrid, Twilio, OpenAI, Anthropic) and generic patterns (private keys, JWTs with
header validation, DB connection strings, basic-auth URLs), plus an optional entropy sweep.

Detectors with an unmistakable structural prefix (`AKIA`, `ghp_`, `sk_live_`) skip the placeholder
screen — a vendor prefix plus 36 random characters can legitimately contain `123456`, and screening
those cost real detections in v1's design.

## Install

```bash
git clone https://github.com/Blueefalcon9/tokenhunter.git
cd tokenhunter
pip install -r requirements.txt   # rich only, and it is optional
```

## Usage

```bash
python3 tokenhunter.py /path/to/project
python3 tokenhunter.py /path/to/repo --git            # include history
python3 tokenhunter.py . --git-only --max-commits 500 # history only, bounded
python3 tokenhunter.py . --fail-on high               # CI gate
```

## Options

| Flag | Default | Description |
|---|---|---|
| `path` | *(required)* | Folder or repo to scan |
| `-o`, `--output` | `output` | Output directory |
| `--git` | off | Also scan git history (added lines) |
| `--git-only` | off | Scan only history, not the worktree |
| `--max-commits` | all | Limit history to N most recent commits |
| `--include-ext` | all text | Comma list of extensions to include |
| `--exclude-dirs` | — | Extra directory names to skip |
| `--max-size` | `2000000` | Max file size in bytes |
| `--max-capture` | `512` | Max captured token length |
| `--entropy` | `4.5` | Entropy threshold for the generic sweep |
| `--no-entropy` | off | Named detectors only |
| `--min-severity` | `low` | Hide findings below this severity |
| `--baseline` | — | JSON of fingerprints to suppress |
| `--write-baseline` | off | Record current findings as the baseline |
| `--unmask` | off | Show full secret values |
| `--fail-on` | — | Exit 1 at/above this severity |
| `--quiet` | off | Suppress the console table |

## Output

`findings.json`, `findings.csv`, and `findings.sarif` (loadable into GitHub code scanning).

## Baselining

Fingerprints hash detector + path + secret, deliberately **excluding the line number**, so ordinary
edits do not churn the baseline:

```bash
python3 tokenhunter.py . --baseline .tokenhunter.json --write-baseline  # accept today's state
python3 tokenhunter.py . --baseline .tokenhunter.json --fail-on high    # fail only on new leaks
```

## Reading the results

`--git` reports secrets that were committed and later deleted, because they are still in history and
still compromised. **Deleting the file is not the fix — rotating the credential is.**

The entropy detector is the noisy one. Raise `--entropy`, exclude build directories, or use
`--no-entropy` before you start suppressing individual findings.

## Authorized use only

Use this only against systems you own or have **written** authorization to test. Unauthorized
scanning and credential discovery are illegal in most jurisdictions. You are responsible for
staying inside your authorized scope.

## License

MIT — see [LICENSE](LICENSE).
