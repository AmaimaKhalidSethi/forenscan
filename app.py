"""
ForenScan — Flask application.
All 9 bugs from the spec are addressed.
"""
import logging
import os
import re
import threading
import time
import uuid
from pathlib import Path

from flask import (
    Flask, flash, redirect, render_template,
    request, send_file, url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename

from analyzer import ForensicAnalyzer
from config import (
    ALLOWED_SCAN_ROOTS,
    BLOCKED_UPLOAD_EXTENSIONS,
    DB_PATH,
    MAX_UPLOAD_SIZE,
    REPORTS_DIR,
    UPLOAD_DIR,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    format='%(asctime)s [%(levelname)s] %(name)s — %(message)s',
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)

# ── Custom Jinja filters ──────────────────────────────────────────────
import json as _json

@app.template_filter('from_json')
def from_json_filter(value):
    try:
        return _json.loads(value)
    except Exception:
        return []

@app.template_filter('filesizeformat')
def filesizeformat_filter(value):
    try:
        v = int(value)
    except (TypeError, ValueError):
        return '—'
    if v < 1024:
        return f'{v} B'
    if v < 1048576:
        return f'{v/1024:.1f} KB'
    if v < 1073741824:
        return f'{v/1048576:.1f} MB'
    return f'{v/1073741824:.1f} GB'

# Bug 2 fixed — load secret key from env; warn if falling back to ephemeral key
_secret = os.environ.get("FORENSCAN_SECRET_KEY")
if not _secret:
    logger.warning(
        "FORENSCAN_SECRET_KEY not set — using ephemeral key. "
        "Sessions will be invalidated on restart."
    )
    _secret = os.urandom(32)
app.secret_key = _secret

app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://",
)

analyzer = ForensicAnalyzer(db_path=DB_PATH)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
    re.IGNORECASE,
)


def _validate_scan_id(scan_id: str) -> str:
    """Bug 7 — validate UUID format before use in SQL or filenames."""
    if not UUID_RE.match(scan_id):
        raise ValueError("Invalid scan_id format")
    return scan_id


def _is_safe_upload(filename: str) -> bool:
    """Bug 5 — reject server-executable extensions."""
    ext = Path(filename).suffix.lower()
    return ext not in BLOCKED_UPLOAD_EXTENSIONS


def _validate_scan_path(dirpath: str) -> str:
    """Bug 1 — resolve and validate path is within allowed roots."""
    resolved = os.path.realpath(os.path.abspath(dirpath))
    for root in ALLOWED_SCAN_ROOTS:
        root_resolved = os.path.realpath(root)
        if resolved.startswith(root_resolved + os.sep) or resolved == root_resolved:
            return resolved
    raise ValueError(f"Path '{dirpath}' is outside permitted scan roots.")


def _cleanup_upload(path: str, delay_seconds: int = 300) -> None:
    """Bug 6 — schedule uploaded file deletion after analysis."""
    def _delete():
        time.sleep(delay_seconds)
        try:
            os.unlink(path)
            logger.info("Cleaned up upload: %s", path)
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.warning("Could not delete upload %s: %s", path, e)

    threading.Thread(target=_delete, daemon=True).start()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    sig_count = analyzer.get_signature_count()
    return render_template("index.html", sig_count=sig_count)


@app.route("/scan", methods=["POST"])
@limiter.limit("10 per minute")
def scan_file():
    if "file" not in request.files:
        flash("No file part in request.", "error")
        return redirect(url_for("index"))

    f = request.files["file"]
    if f.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("index"))

    original_name = f.filename
    # Bug 5 — safe upload check
    if not _is_safe_upload(original_name):
        flash("File type not permitted for upload.", "error")
        return redirect(url_for("index"))

    safe_name = secure_filename(original_name)
    scan_id = str(uuid.uuid4())
    # Save with UUID prefix — never use original filename as path component
    dest_filename = f"{scan_id}_{safe_name}"
    dest_path = os.path.join(UPLOAD_DIR, dest_filename)

    try:
        f.save(dest_path)
    except OSError as e:
        flash(f"Could not save upload: {e}", "error")
        return redirect(url_for("index"))

    # Full analysis
    analyzer.analyze_file(dest_path, scan_id)

    # Bug 4 fixed — use analyzer method to update filename, not raw SQL
    analyzer.update_filename(scan_id, original_name)

    # Bug 6 — schedule cleanup
    _cleanup_upload(dest_path)

    return redirect(url_for("results", scan_id=scan_id))


@app.route("/scan-directory", methods=["POST"])
@limiter.limit("5 per minute")
def scan_directory():
    dirpath = request.form.get("dirpath", "").strip()
    if not dirpath:
        flash("No directory path provided.", "error")
        return redirect(url_for("index"))

    # Bug 1 fixed — validate against whitelist
    try:
        safe_path = _validate_scan_path(dirpath)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("index"))

    if not os.path.isdir(safe_path):
        flash(f"Directory not found: {safe_path}", "error")
        return redirect(url_for("index"))

    scan_id = str(uuid.uuid4())
    try:
        analyzer.scan_directory(safe_path, scan_id)
    except Exception as e:
        logger.exception("Directory scan failed for %s", safe_path)
        flash(f"Scan failed: {e}", "error")
        return redirect(url_for("index"))

    return redirect(url_for("results", scan_id=scan_id))


@app.route("/results/<scan_id>")
def results(scan_id):
    # Bug 9 fixed — wrap in try/except
    try:
        _validate_scan_id(scan_id)
        scan_results = analyzer.get_scan_results(scan_id)
    except ValueError:
        flash("Invalid scan ID.", "error")
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"Error retrieving scan: {e}", "error")
        return redirect(url_for("index"))

    if not scan_results:
        flash("No results found for this scan ID.", "error")
        return redirect(url_for("index"))

    # Summary stats
    stats = {
        "total": len(scan_results),
        "critical": sum(1 for r in scan_results if r["risk_level"] == "CRITICAL"),
        "high": sum(1 for r in scan_results if r["risk_level"] == "HIGH"),
        "medium": sum(1 for r in scan_results if r["risk_level"] == "MEDIUM"),
        "low": sum(1 for r in scan_results if r["risk_level"] == "LOW"),
        "anomalies": sum(1 for r in scan_results if r["anomaly_flag"]),
    }
    return render_template("results.html", results=scan_results, scan_id=scan_id, stats=stats)


@app.route("/export/<scan_id>/<fmt>")
def export(scan_id, fmt):
    try:
        _validate_scan_id(scan_id)
    except ValueError:
        flash("Invalid scan ID.", "error")
        return redirect(url_for("index"))

    if fmt not in ("json", "csv"):
        flash("Unknown export format.", "error")
        return redirect(url_for("results", scan_id=scan_id))

    os.makedirs(REPORTS_DIR, exist_ok=True)
    # scan_id is UUID-validated above — safe for filename use
    output_path = os.path.join(REPORTS_DIR, f"{scan_id}.{fmt}")

    try:
        if fmt == "json":
            analyzer.export_json(scan_id, output_path)
            mime = "application/json"
        else:
            analyzer.export_csv(scan_id, output_path)
            mime = "text/csv"
    except Exception as e:
        flash(f"Export failed: {e}", "error")
        return redirect(url_for("results", scan_id=scan_id))

    return send_file(output_path, mimetype=mime, as_attachment=True,
                     download_name=f"forenscan_{scan_id}.{fmt}")


@app.route("/signatures")
def signatures():
    sigs = analyzer.get_all_signatures()
    categories = sorted({s["category"] for s in sigs})
    return render_template("signatures.html", signatures=sigs, categories=categories)


@app.route("/history")
def history():
    hist = analyzer.get_scan_history()
    return render_template("history.html", history=hist)


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(413)
def too_large(e):
    flash("File too large. Maximum upload size is 50MB.", "error")
    return redirect(url_for("index"))


@app.errorhandler(429)
def rate_limited(e):
    flash("Too many requests. Please wait before scanning again.", "error")
    return redirect(url_for("index"))


if __name__ == "__main__":
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    app.run(debug=False, host="0.0.0.0", port=5050)
