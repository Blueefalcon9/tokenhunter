# TokenHunter

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Scan a folder or git repository for leaked credentials — API keys, tokens, JWTs, and high-entropy strings.
Findings are **masked by default** (last 4 characters only) so output is safe to paste into a ticket.

## What it detects

| Detector | Pattern |
|---|---|
| AWS Access Key ID | `AKIA`/`ASIA` + 16 chars |
| AWS Secret Key | 40-char base64, boundary-anchored |
| Google API Key | `AIza` + 35 chars |
| Slack Token | `xox[baprs]-` |
| Bearer Token | `Bearer <token>` |
| JWT | `header.payload.signature` |
| Generic API Key | `api`/`secret`/`token`/`key`/`password` followed by 16+ chars |
| High entropy | Shannon entropy above threshold (default 4.0) |

## Install

```bash
git clone https://github.com/Blueefalcon9/tokenhunter.git
cd tokenhunter
pip install -r requirements.txt
```

## Usage

```bash
python3 tokenhunter.py /path/to/project
python3 tokenhunter.py /path/to/repo --git -o findings
python3 tokenhunter.py . --entropy 4.5 --exclude-dirs node_modules,dist
```

## Options

| Flag | Default | Description |
|---|---|---|
| `path` | *(required)* | Folder or repo to scan |
| `-o`, `--output` | `output` | Output directory |
| `--git` | off | Also scan git history (added lines across all commits) |
| `--include-ext` | all | Comma-separated extensions to include |
| `--exclude-dirs` | — | Comma-separated directory names to skip |
| `--max-size` | `2000000` | Max file size to read, in bytes |
| `--max-capture` | `512` | Max length of a captured token |
| `--entropy` | `4.0` | Shannon entropy threshold for generic tokens |

## Output

Rich console table plus `findings.csv` and `findings.json`. Binaries and oversized files are skipped
automatically.

## Tuning the entropy threshold

The generic high-entropy detector is the noisy one. Minified JS, lockfiles, base64 assets, and UUIDs all trip
it. If you are drowning in false positives, raise `--entropy` to 4.5 and exclude build directories before you
start suppressing individual findings.

`--git` scans added lines across history, so a secret that was committed and later removed still surfaces —
which is usually the point. Note that rotating the credential, not deleting the file, is the fix.

## Authorized use only

Use this only against systems you own or have **written** authorization to test. Unauthorized scanning and
credential discovery are illegal in most jurisdictions. You are responsible for staying inside your
authorized scope.

## License

MIT — see [LICENSE](LICENSE).
