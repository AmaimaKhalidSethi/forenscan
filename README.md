# ForenScan

**Production-grade digital forensics file analysis system.**

Magic-number detection · Cryptographic hashing · Hex visualization · Anomaly detection · Chain-of-custody export

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. (Recommended) Set a stable secret key
export FORENSCAN_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"

# 3. Run
python app.py
# → http://localhost:5050
```

---

## Features

| Capability | Detail |
|---|---|
| Magic-number detection | 22+ signatures, longest-match-wins algorithm |
| Hashing | Streaming MD5 + SHA-256 (64KB chunks, NIST-compliant) |
| Hex preview | First 64 bytes in xxd-compatible address/hex/ASCII format |
| Anomaly detection | Extension mismatch, executable-in-document, high entropy (>7.2 bits/byte) |
| YARA-lite patterns | Scans for `CreateRemoteThread`, `VirtualAlloc`, `WScript.Shell`, `cmd.exe /c` |
| Entropy analysis | Per-file Shannon entropy — flags encrypted/packed files |
| Footer verification | Validates end-of-file signatures (e.g. JPEG `FF D9`, PNG IEND) |
| Chain-of-custody export | JSON with metadata envelope + flat CSV for Autopsy/FTK |
| Rate limiting | 10 scans/min per IP on `/scan`, 5/min on `/scan-directory` |

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `FORENSCAN_SECRET_KEY` | Random (ephemeral) | Flask session key — **set this in production** |

### Allowed Scan Roots

Directory scanning is restricted to whitelisted paths to prevent path traversal.
Edit `config.py` to add your evidence directories:

```python
ALLOWED_SCAN_ROOTS = [
    os.path.join(BASE_DIR, "evidence"),   # ./evidence/ (default)
    "/tmp/forensic_evidence",             # add your paths here
    "/mnt/evidence",
]
```

Paths outside this list are rejected at the API level.

### Upload Limits

- Maximum file size: **50 MB** (`MAX_UPLOAD_SIZE` in `config.py`)
- Directory scan file limit: **500 files** per session
- Files >500 MB in directory scans are skipped
- Blocked upload extensions: `.php .py .rb .sh .pl .cgi .asp .aspx .exe .bat .cmd .ps1`

---

## Security Model

| Control | Implementation |
|---|---|
| Path traversal | `ALLOWED_SCAN_ROOTS` + `os.path.realpath()` validation |
| Upload safety | Extension blocklist + `secure_filename()` |
| Filename isolation | UUID-prefixed paths — original filename never used as filesystem path |
| SQL injection | 100% parameterized queries |
| Session security | `FORENSCAN_SECRET_KEY` env var (logged warning if missing) |
| scan_id validation | UUID4 regex before any SQL or filesystem use |
| Temp file cleanup | Auto-deleted 5 minutes after analysis via daemon thread |
| Rate limiting | Flask-Limiter per-IP with memory backend |

---

## Project Structure

```
forenscan/
├── app.py                    # Flask application (all 9 bugs fixed)
├── analyzer.py               # ForensicAnalyzer class
├── config.py                 # Configuration constants
├── forensic_signatures.db    # SQLite — auto-created on first run
├── utils/
│   ├── hex_utils.py          # xxd-style hex formatting
│   ├── hash_utils.py         # Streaming MD5/SHA-256
│   └── export_utils.py       # JSON/CSV serialization
├── templates/
│   ├── base.html             # Layout, navbar, CSS variables
│   ├── index.html            # Dashboard + upload forms
│   ├── results.html          # Scan results viewer
│   ├── signatures.html       # Signature database browser
│   └── history.html          # Past scan sessions
├── static/
│   ├── css/theme.css         # Full design system
│   └── js/app.js             # Drag-drop, hash copy, spinners
├── uploads/                  # Temp uploads (auto-cleaned)
├── reports/                  # Exported reports
└── evidence/                 # Default allowed scan root
```

---

## Bugs Fixed (from spec)

| # | Bug | Fix |
|---|---|---|
| 1 | Directory traversal in `/scan-directory` | `ALLOWED_SCAN_ROOTS` + `_validate_scan_path()` |
| 2 | `secret_key = os.urandom(32)` on every restart | Load from `FORENSCAN_SECRET_KEY` env var |
| 3 | Inline `import sqlite3` inside route functions | All imports at module top level |
| 4 | Raw SQL bypassing analyzer after `analyze_file()` | `analyzer.update_filename()` method |
| 5 | No file type validation on upload | `BLOCKED_UPLOAD_EXTENSIONS` + `_is_safe_upload()` |
| 6 | Uploaded files never cleaned up | `_cleanup_upload()` daemon thread, 5-min delay |
| 7 | `scan_id` not validated in `/export` and `/results` | UUID4 regex `_validate_scan_id()` |
| 8 | No rate limiting on scan endpoints | Flask-Limiter: 10/min file, 5/min directory |
| 9 | Missing error handling in results route | Full `try/except` with flash + redirect |
| 10 | `{{ sig_count }}` unevaluated inside Jinja string literal | Constructed outside `{% set %}` string |
| 11 | Dir scan spinner fires on empty path | `e.preventDefault()` guard before showing spinner |
| 12 | `footer_valid` ternary logic ambiguity | Explicit three-way `{% if %}` / `{% elif %}` / `{% else %}` |
| 13 | Collapse header missing `role="button"` + keyboard | `role="button"`, `tabindex="0"`, `onkeydown` handler |
| 14 | `return false` instead of `e.preventDefault()` | `filterCat(cat, el, event)` + `event.preventDefault()` |
| 15 | No text search on signatures table | Live `#sigSearch` input + `filterSigs()` + combined filter |

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Dashboard |
| `POST` | `/scan` | Upload + analyze a single file |
| `POST` | `/scan-directory` | Scan a whitelisted directory |
| `GET` | `/results/<scan_id>` | View scan results |
| `GET` | `/export/<scan_id>/json` | Download JSON report |
| `GET` | `/export/<scan_id>/csv` | Download CSV report |
| `GET` | `/signatures` | Browse signature database |
| `GET` | `/history` | View scan session history |