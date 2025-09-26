Features
  Recursively scans files (with size and extension filters)

Detects:
  AWS Access Keys & Secrets
  Google API keys
  Slack tokens
  GitHub tokens & PATs
  Bearer tokens
  JWTs (header.payload.signature)
  Generic high-entropy strings

Optional: scan git history (--git)
  Masks secrets in console/CSV/JSON output (last 4 chars visible)
  Ignores binaries and large files by default
  Pretty console table (Rich) + CSV/JSON export

Usage 
python3 tokenhunter.py /path/to/project --git -o output
