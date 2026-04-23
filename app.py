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


@app.route("/signatures/add", methods=["GET", "POST"])
@limiter.limit("30 per hour")
def add_signature():
    """Add a custom signature with full validation."""
    VALID_CATEGORIES = [
        "IMAGE", "DOCUMENT", "ARCHIVE", "EXECUTABLE", "SCRIPT",
        "MEDIA", "SYSTEM", "CRYPTO", "FORENSIC", "FONT", "DATABASE",
        "CAD", "GIS", "GAME", "CONTAINER", "MOBILE", "WEB",
        "EMAIL", "DISK",
    ]
    VALID_RISK_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    if request.method == "GET":
        return render_template(
            "add_signature.html",
            categories=VALID_CATEGORIES,
            risk_levels=VALID_RISK_LEVELS,
            prefill={},
            errors={},
        )

    # ── Collect fields ────────────────────────────────────────────────
    fields = {
        "name":       request.form.get("name", "").strip(),
        "category":   request.form.get("category", "").strip().upper(),
        "mime_type":  request.form.get("mime_type", "").strip(),
        "header_hex": request.form.get("header_hex", "").strip().upper(),
        "footer_hex": request.form.get("footer_hex", "").strip().upper() or None,
        "extensions": request.form.get("extensions", "").strip().lower(),
        "risk_level": request.form.get("risk_level", "").strip().upper(),
        "notes":      request.form.get("notes", "").strip(),
    }

    errors = _validate_signature_fields(fields, VALID_CATEGORIES, VALID_RISK_LEVELS)

    if errors:
        return render_template(
            "add_signature.html",
            categories=VALID_CATEGORIES,
            risk_levels=VALID_RISK_LEVELS,
            prefill=fields,
            errors=errors,
        )

    # ── Normalise hex strings ────────────────────────────────────────
    fields["header_hex"] = _normalise_hex(fields["header_hex"])
    if fields["footer_hex"]:
        fields["footer_hex"] = _normalise_hex(fields["footer_hex"])

    # ── Serialise extensions to JSON array ───────────────────────────
    ext_list = [e.strip().lstrip(".") for e in fields["extensions"].replace(",", " ").split() if e.strip()]
    extensions_json = _json.dumps(ext_list)

    try:
        sig_id = analyzer.add_signature(
            name=fields["name"],
            category=fields["category"],
            mime_type=fields["mime_type"],
            header_hex=fields["header_hex"],
            footer_hex=fields["footer_hex"],
            extensions=extensions_json,
            risk_level=fields["risk_level"],
        )
        flash(f"Signature '{fields['name']}' added successfully (ID {sig_id}).", "success")
        return redirect(url_for("signatures"))
    except Exception as e:
        flash(f"Database error: {e}", "error")
        return render_template(
            "add_signature.html",
            categories=VALID_CATEGORIES,
            risk_levels=VALID_RISK_LEVELS,
            prefill=fields,
            errors={},
        )


@app.route("/signatures/edit/<int:sig_id>", methods=["GET", "POST"])
@limiter.limit("30 per hour")
def edit_signature(sig_id):
    """Edit an existing signature."""
    VALID_CATEGORIES = [
        "IMAGE", "DOCUMENT", "ARCHIVE", "EXECUTABLE", "SCRIPT",
        "MEDIA", "SYSTEM", "CRYPTO", "FORENSIC", "FONT", "DATABASE",
        "CAD", "GIS", "GAME", "CONTAINER", "MOBILE", "WEB",
        "EMAIL", "DISK",
    ]
    VALID_RISK_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    sig = analyzer.get_signature_by_id(sig_id)
    if not sig:
        flash("Signature not found.", "error")
        return redirect(url_for("signatures"))

    if request.method == "GET":
        # Pre-fill extensions as comma-separated plain text
        try:
            ext_list = _json.loads(sig["extensions"])
            ext_plain = ", ".join(ext_list)
        except Exception:
            ext_plain = sig["extensions"]

        prefill = dict(sig)
        prefill["extensions"] = ext_plain
        return render_template(
            "add_signature.html",
            categories=VALID_CATEGORIES,
            risk_levels=VALID_RISK_LEVELS,
            prefill=prefill,
            errors={},
            edit_mode=True,
            sig_id=sig_id,
        )

    fields = {
        "name":       request.form.get("name", "").strip(),
        "category":   request.form.get("category", "").strip().upper(),
        "mime_type":  request.form.get("mime_type", "").strip(),
        "header_hex": request.form.get("header_hex", "").strip().upper(),
        "footer_hex": request.form.get("footer_hex", "").strip().upper() or None,
        "extensions": request.form.get("extensions", "").strip().lower(),
        "risk_level": request.form.get("risk_level", "").strip().upper(),
        "notes":      request.form.get("notes", "").strip(),
    }

    errors = _validate_signature_fields(fields, VALID_CATEGORIES, VALID_RISK_LEVELS)

    if errors:
        return render_template(
            "add_signature.html",
            categories=VALID_CATEGORIES,
            risk_levels=VALID_RISK_LEVELS,
            prefill=fields,
            errors=errors,
            edit_mode=True,
            sig_id=sig_id,
        )

    fields["header_hex"] = _normalise_hex(fields["header_hex"])
    if fields["footer_hex"]:
        fields["footer_hex"] = _normalise_hex(fields["footer_hex"])

    ext_list = [e.strip().lstrip(".") for e in fields["extensions"].replace(",", " ").split() if e.strip()]
    extensions_json = _json.dumps(ext_list)

    try:
        analyzer.update_signature(
            sig_id=sig_id,
            name=fields["name"],
            category=fields["category"],
            mime_type=fields["mime_type"],
            header_hex=fields["header_hex"],
            footer_hex=fields["footer_hex"],
            extensions=extensions_json,
            risk_level=fields["risk_level"],
        )
        flash(f"Signature '{fields['name']}' updated.", "success")
        return redirect(url_for("signatures"))
    except Exception as e:
        flash(f"Update failed: {e}", "error")
        return redirect(url_for("signatures"))


@app.route("/signatures/delete/<int:sig_id>", methods=["POST"])
@limiter.limit("20 per hour")
def delete_signature(sig_id):
    """Delete a signature by ID."""
    sig = analyzer.get_signature_by_id(sig_id)
    if not sig:
        flash("Signature not found.", "error")
        return redirect(url_for("signatures"))

    try:
        analyzer.delete_signature(sig_id)
        flash(f"Signature '{sig['name']}' deleted.", "success")
    except Exception as e:
        flash(f"Delete failed: {e}", "error")
    return redirect(url_for("signatures"))


@app.route("/signatures/verify", methods=["POST"])
def verify_signature_hex():
    """AJAX endpoint — validate hex string and return parsed bytes + preview."""
    hex_str = request.json.get("hex", "").strip().upper()
    result = _parse_hex_preview(hex_str)
    return result


# ---------------------------------------------------------------------------
# Signature validation helpers
# ---------------------------------------------------------------------------

def _normalise_hex(hex_str: str) -> str:
    """Normalise hex: strip spaces, insert spaces between every byte pair."""
    cleaned = hex_str.replace(" ", "").replace(":", "").replace("-", "")
    if len(cleaned) % 2 != 0:
        return hex_str  # will be caught by validator
    return " ".join(cleaned[i:i+2] for i in range(0, len(cleaned), 2))


def _parse_hex_preview(hex_str: str) -> dict:
    """
    Parse a hex string and return validation result with byte preview.
    Returns JSON-serialisable dict: { valid, bytes_count, preview, error }
    """
    from flask import jsonify
    if not hex_str:
        return jsonify({"valid": False, "error": "Empty hex string"})

    # Accept formats: "FF D8 FF", "FFD8FF", "FF:D8:FF", "0xFF 0xD8"
    cleaned = (hex_str
               .replace("0X", "").replace("0x", "")
               .replace(":", "").replace("-", "").replace(" ", ""))

    if not all(c in "0123456789ABCDEF" for c in cleaned):
        return jsonify({"valid": False, "error": "Invalid characters — hex only (0-9, A-F)"})

    if len(cleaned) % 2 != 0:
        return jsonify({"valid": False, "error": "Odd number of hex digits — each byte needs 2 digits"})

    if len(cleaned) < 2:
        return jsonify({"valid": False, "error": "At least 1 byte (2 hex digits) required"})

    if len(cleaned) > 64:
        return jsonify({"valid": False, "error": "Maximum 32 bytes (64 hex digits) for header signature"})

    byte_vals = [int(cleaned[i:i+2], 16) for i in range(0, len(cleaned), 2)]
    normalised = " ".join(f"{b:02X}" for b in byte_vals)
    ascii_repr = "".join(chr(b) if 32 <= b < 127 else "·" for b in byte_vals)

    return jsonify({
        "valid": True,
        "bytes_count": len(byte_vals),
        "normalised": normalised,
        "ascii_repr": ascii_repr,
        "preview": [{"hex": f"{b:02X}", "dec": b, "ascii": chr(b) if 32 <= b < 127 else "·"} for b in byte_vals],
    })


def _validate_signature_fields(fields: dict, valid_categories: list, valid_risk_levels: list) -> dict:
    """
    Full server-side validation of all signature fields.
    Returns dict of {field_name: error_message}. Empty dict = valid.
    """
    import re as _re
    errors = {}

    # ── Name ────────────────────────────────────────────────────────
    if not fields["name"]:
        errors["name"] = "Name is required."
    elif len(fields["name"]) > 80:
        errors["name"] = "Name must be 80 characters or fewer."
    elif not _re.match(r'^[\w\s\-\./\(\)]+$', fields["name"]):
        errors["name"] = "Name contains invalid characters."

    # ── Category ────────────────────────────────────────────────────
    if not fields["category"]:
        errors["category"] = "Category is required."
    elif fields["category"] not in valid_categories:
        errors["category"] = f"Invalid category. Choose from: {', '.join(valid_categories)}"

    # ── MIME type ────────────────────────────────────────────────────
    if not fields["mime_type"]:
        errors["mime_type"] = "MIME type is required."
    elif len(fields["mime_type"]) > 100:
        errors["mime_type"] = "MIME type too long (max 100 chars)."
    elif not _re.match(r'^[a-zA-Z0-9][a-zA-Z0-9!\#\$&\-\^_]*\/[a-zA-Z0-9][a-zA-Z0-9!\#\$&\-\^\._\+]*$', fields["mime_type"]):
        errors["mime_type"] = "Invalid MIME type format (expected type/subtype, e.g. image/jpeg)."

    # ── Header hex ──────────────────────────────────────────────────
    if not fields["header_hex"]:
        errors["header_hex"] = "Header hex is required."
    else:
        cleaned = (fields["header_hex"]
                   .replace(" ", "").replace(":", "").replace("-", "")
                   .replace("0X", "").replace("0x", ""))
        if not all(c in "0123456789ABCDEFabcdef" for c in cleaned):
            errors["header_hex"] = "Contains invalid characters. Use hex digits only (0–9, A–F)."
        elif len(cleaned) % 2 != 0:
            errors["header_hex"] = "Odd number of hex digits — each byte needs 2 digits (e.g. FF D8 FF)."
        elif len(cleaned) < 2:
            errors["header_hex"] = "At least 1 byte required."
        elif len(cleaned) > 64:
            errors["header_hex"] = "Maximum 32 bytes allowed for header signature."
        else:
            # Check it's not all zeros (almost certainly wrong)
            byte_vals = [int(cleaned[i:i+2], 16) for i in range(0, len(cleaned), 2)]
            if all(b == 0 for b in byte_vals):
                errors["header_hex"] = "All-zero header is too generic — choose a more specific signature."

    # ── Footer hex (optional) ────────────────────────────────────────
    if fields["footer_hex"]:
        cleaned_f = (fields["footer_hex"]
                     .replace(" ", "").replace(":", "").replace("-", "")
                     .replace("0X", "").replace("0x", ""))
        if not all(c in "0123456789ABCDEFabcdef" for c in cleaned_f):
            errors["footer_hex"] = "Contains invalid characters."
        elif len(cleaned_f) % 2 != 0:
            errors["footer_hex"] = "Odd number of hex digits."
        elif len(cleaned_f) > 32:
            errors["footer_hex"] = "Maximum 16 bytes for footer."

    # ── Extensions ──────────────────────────────────────────────────
    if not fields["extensions"]:
        errors["extensions"] = "At least one file extension is required."
    else:
        ext_list = [e.strip().lstrip(".") for e in fields["extensions"].replace(",", " ").split() if e.strip()]
        if not ext_list:
            errors["extensions"] = "Could not parse any extensions."
        elif len(ext_list) > 20:
            errors["extensions"] = "Too many extensions (max 20)."
        else:
            bad = [e for e in ext_list if not _re.match(r'^[a-zA-Z0-9_\-]{1,16}$', e)]
            if bad:
                errors["extensions"] = f"Invalid extension(s): {', '.join(bad)} — use letters, digits, hyphens only."

    # ── Risk level ───────────────────────────────────────────────────
    if not fields["risk_level"]:
        errors["risk_level"] = "Risk level is required."
    elif fields["risk_level"] not in valid_risk_levels:
        errors["risk_level"] = f"Must be one of: {', '.join(valid_risk_levels)}"

    # ── Cross-check: CRITICAL only for EXECUTABLE category ──────────
    if (fields.get("risk_level") == "CRITICAL"
            and fields.get("category") not in ("EXECUTABLE", "SCRIPT")):
        errors["risk_level"] = "CRITICAL risk is reserved for EXECUTABLE or SCRIPT categories."

    # ── Duplicate check: same header_hex + same first extension ─────
    if "header_hex" not in errors and "extensions" not in errors:
        try:
            ext_list = [e.strip().lstrip(".") for e in fields["extensions"].replace(",", " ").split() if e.strip()]
            dup = analyzer.find_duplicate_signature(
                _normalise_hex(fields["header_hex"]), ext_list[0] if ext_list else ""
            )
            if dup:
                errors["header_hex"] = (
                    f"Duplicate: signature '{dup['name']}' already uses this header hex "
                    f"with .{ext_list[0]} extension (ID {dup['id']})."
                )
        except Exception:
            pass  # don't block submission on duplicate-check errors

    return errors


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