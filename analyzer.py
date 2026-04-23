"""
ForensicAnalyzer — core analysis engine.

Responsibilities:
  - Signature matching (magic number detection via SQLite DB)
  - Cryptographic hashing (MD5 + SHA-256, streaming 64KB chunks)
  - Hex-stream extraction (xxd-style rows)
  - Anomaly detection (extension mismatch, executable-in-document)
  - Entropy analysis
  - Persistence (SQLite scan_results)
  - Export (JSON + CSV)
"""
import collections
import datetime
import json
import logging
import math
import os
import sqlite3

from config import DB_PATH, CHUNK_SIZE, MAX_FILE_SIZE_SCAN, MAX_DIR_FILES
from utils.hex_utils import extract_hex_preview
from utils.hash_utils import compute_hashes
from utils.export_utils import export_json, export_csv

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Anomaly rules: (detected_category, suspicious_declared_exts, reason, risk)
# ---------------------------------------------------------------------------
ANOMALY_RULES = [
    (
        "EXECUTABLE",
        {"jpg", "jpeg", "png", "gif", "pdf", "doc", "docx", "xls", "xlsx", "mp3", "mp4"},
        "Executable disguised as media/document file",
        "CRITICAL",
    ),
    (
        "SCRIPT",
        {"jpg", "jpeg", "png", "gif", "pdf", "zip"},
        "Script file with non-script extension",
        "HIGH",
    ),
    (
        "EXECUTABLE",
        {"zip", "rar", "7z"},
        "Executable embedded in archive extension — possible exploit",
        "CRITICAL",
    ),
]

SUSPICIOUS_STRINGS = [
    b"CreateRemoteThread",
    b"VirtualAlloc",
    b"WScript.Shell",
    b"cmd.exe /c",
]

HIGH_ENTROPY_THRESHOLD = 7.2


class ForensicAnalyzer:

    CHUNK_SIZE = CHUNK_SIZE

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS signatures (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    name        TEXT NOT NULL,
                    category    TEXT NOT NULL,
                    mime_type   TEXT NOT NULL,
                    header_hex  TEXT NOT NULL,
                    footer_hex  TEXT,
                    extensions  TEXT NOT NULL,
                    risk_level  TEXT NOT NULL
                        CHECK(risk_level IN ('CRITICAL','HIGH','MEDIUM','LOW'))
                );

                CREATE TABLE IF NOT EXISTS scan_results (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id         TEXT NOT NULL,
                    filename        TEXT NOT NULL,
                    filepath        TEXT NOT NULL,
                    detected_type   TEXT,
                    mime_type       TEXT,
                    declared_ext    TEXT,
                    risk_level      TEXT DEFAULT 'UNKNOWN',
                    anomaly_flag    INTEGER DEFAULT 0,
                    anomaly_reason  TEXT,
                    md5_hash        TEXT,
                    sha256_hash     TEXT,
                    file_size       INTEGER,
                    scan_timestamp  TEXT,
                    footer_valid    INTEGER,
                    hex_preview     TEXT,
                    error           TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id
                    ON scan_results(scan_id);
                CREATE INDEX IF NOT EXISTS idx_signatures_category
                    ON signatures(category);
            """)
        self._seed_signatures()

    def _seed_signatures(self) -> None:
        """Populate signatures if the table is empty using the full 185+ entry database builder."""
        with self._get_connection() as conn:
            count = conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
            if count > 0:
                return

        try:
            from build_signatures_db import build_database
            build_database(self.db_path)
            with self._get_connection() as conn:
                count = conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
            logger.info("Signature database seeded: %d entries across 19 categories", count)
        except Exception as e:
            logger.error("Failed to seed from build_signatures_db: %s — falling back to minimal set", e)
            self._seed_minimal_fallback()

    def _seed_minimal_fallback(self) -> None:
        """Emergency minimal seed if the full builder fails."""
        with self._get_connection() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO signatures "
                "(name,category,mime_type,header_hex,footer_hex,extensions,risk_level)"
                " VALUES (?,?,?,?,?,?,?)",
                [
                    ("JPEG Image",    "IMAGE",      "image/jpeg",             "FF D8 FF", "FF D9",        '["jpg","jpeg"]', "LOW"),
                    ("PNG Image",     "IMAGE",      "image/png",              "89 50 4E 47 0D 0A 1A 0A", None, '["png"]', "LOW"),
                    ("PDF Document",  "DOCUMENT",   "application/pdf",        "25 50 44 46", None,        '["pdf"]',    "LOW"),
                    ("ZIP Archive",   "ARCHIVE",    "application/zip",        "50 4B 03 04", None,        '["zip"]',    "MEDIUM"),
                    ("Windows EXE",   "EXECUTABLE", "application/x-msdownload","4D 5A",    None,         '["exe","dll"]',"HIGH"),
                    ("ELF Binary",    "EXECUTABLE", "application/x-elf",      "7F 45 4C 46", None,       '["elf","so"]', "HIGH"),
                    ("SQLite DB",     "DATABASE",   "application/x-sqlite3",  "53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00", None, '["db","sqlite"]', "MEDIUM"),
                ]
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_file(self, filepath: str, scan_id: str) -> dict:
        """
        Full analysis pipeline for a single file.
        Returns result dict. Never raises — errors captured in result['error'].
        """
        result: dict = {
            "scan_id": scan_id,
            "filename": os.path.basename(filepath),
            "filepath": filepath,
            "detected_type": None,
            "mime_type": None,
            "declared_ext": None,
            "risk_level": "UNKNOWN",
            "anomaly_flag": False,
            "anomaly_reason": None,
            "md5_hash": None,
            "sha256_hash": None,
            "file_size": None,
            "scan_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "footer_valid": None,
            "hex_preview": [],
            "error": None,
            "entropy": None,
            "yara_hits": [],
        }
        try:
            result["file_size"] = os.path.getsize(filepath)

            # Read up to 512 bytes for signature matching (supports offset-128 DICOM etc.)
            with open(filepath, 'rb') as f:
                header_bytes_full = f.read(512)
            # Primary match uses first 64 bytes; fallback scans known offsets
            header_bytes = header_bytes_full[:64]

            # Hex preview
            result["hex_preview"] = extract_hex_preview(filepath, 64)

            # Signature match — pass declared extension for disambiguation
            declared_ext = os.path.splitext(filepath)[1].lstrip('.').lower()
            result["declared_ext"] = declared_ext
            sig = self._match_signature(header_bytes, declared_ext)

            # DICOM offset-128 fallback: if no match on first 64B, try offset 128
            if sig is None and len(header_bytes_full) >= 132:
                dicom_candidate = header_bytes_full[128:132]
                if dicom_candidate == b'DICM':
                    with self._get_connection() as conn:
                        dicom_row = conn.execute(
                            "SELECT * FROM signatures WHERE name LIKE '%DICOM%' LIMIT 1"
                        ).fetchone()
                    if dicom_row:
                        sig = dict(dicom_row)

            if sig:
                result["detected_type"] = sig["name"]
                result["mime_type"] = sig["mime_type"]
                result["risk_level"] = sig["risk_level"]

                # Footer verification
                result["footer_valid"] = self._verify_footer(filepath, sig["footer_hex"])

                # Anomaly detection
                exts = json.loads(sig["extensions"])
                is_anomaly, reason = self._detect_anomaly(
                    sig["category"], declared_ext, sig["mime_type"]
                )
                result["anomaly_flag"] = is_anomaly
                result["anomaly_reason"] = reason
            else:
                result["detected_type"] = "UNKNOWN"

            # Hashes
            result["md5_hash"], result["sha256_hash"] = compute_hashes(filepath)

            # Entropy
            with open(filepath, 'rb') as f:
                sample = f.read(65536)  # first 64KB for entropy
            result["entropy"] = round(self._compute_entropy(sample), 4)

            # Flag high-entropy non-compressed files
            if (result["entropy"] or 0) > HIGH_ENTROPY_THRESHOLD:
                compressed_cats = {"ARCHIVE", "MEDIA"}
                cat = sig["category"] if sig else ""
                if cat not in compressed_cats:
                    result["anomaly_flag"] = True
                    extra = f"High entropy ({result['entropy']} bits/byte) — possible encryption or packing"
                    result["anomaly_reason"] = (
                        (result["anomaly_reason"] + "; " + extra)
                        if result["anomaly_reason"]
                        else extra
                    )
                    if result["risk_level"] in ("UNKNOWN", "LOW"):
                        result["risk_level"] = "HIGH"

            # YARA-lite pattern scan
            result["yara_hits"] = self._yara_lite_scan(filepath)
            if result["yara_hits"]:
                hit_str = "Suspicious strings: " + ", ".join(
                    f"'{h['pattern']}' @{h['offset']}" for h in result["yara_hits"]
                )
                result["anomaly_flag"] = True
                result["anomaly_reason"] = (
                    (result["anomaly_reason"] + "; " + hit_str)
                    if result["anomaly_reason"]
                    else hit_str
                )
                if result["risk_level"] in ("UNKNOWN", "LOW", "MEDIUM"):
                    result["risk_level"] = "HIGH"

        except PermissionError as e:
            result["error"] = f"Permission denied: {e}"
            logger.warning("Permission denied reading %s: %s", filepath, e)
        except IsADirectoryError as e:
            result["error"] = f"Is a directory: {e}"
        except OSError as e:
            result["error"] = f"OS error: {e}"
            logger.error("OSError analyzing %s: %s", filepath, e)
        except Exception as e:
            result["error"] = f"Unexpected error: {e}"
            logger.exception("Unexpected error analyzing %s", filepath)

        self._persist_result(result)
        return result

    def scan_directory(self, dirpath: str, scan_id: str) -> list[dict]:
        """
        Recursively scan all files in dirpath.
        Skips symlinks and files >500MB. Caps at MAX_DIR_FILES.
        """
        results = []
        count = 0
        for root, dirs, files in os.walk(dirpath):
            # Skip hidden dirs
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for fname in files:
                if count >= MAX_DIR_FILES:
                    logger.warning("Directory scan capped at %d files", MAX_DIR_FILES)
                    return results
                fpath = os.path.join(root, fname)
                if os.path.islink(fpath):
                    continue
                try:
                    size = os.path.getsize(fpath)
                except OSError:
                    continue
                if size > MAX_FILE_SIZE_SCAN:
                    logger.info("Skipping large file: %s (%d bytes)", fpath, size)
                    continue
                results.append(self.analyze_file(fpath, scan_id))
                count += 1
        return results

    def update_filename(self, scan_id: str, filename: str) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE scan_results SET filename = ? WHERE scan_id = ?",
                (filename, scan_id),
            )

    def get_scan_results(self, scan_id: str) -> list[dict]:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_results WHERE scan_id = ? ORDER BY "
                "CASE risk_level "
                "  WHEN 'CRITICAL' THEN 1 "
                "  WHEN 'HIGH'     THEN 2 "
                "  WHEN 'MEDIUM'   THEN 3 "
                "  WHEN 'LOW'      THEN 4 "
                "  ELSE 5 END",
                (scan_id,),
            ).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            # Decode hex_preview JSON
            try:
                d["hex_preview"] = json.loads(d["hex_preview"]) if d["hex_preview"] else []
            except Exception:
                d["hex_preview"] = []
            # Normalise footer_valid: integer → bool/None
            if d["footer_valid"] is None:
                d["footer_valid"] = None
            else:
                d["footer_valid"] = bool(d["footer_valid"])
            results.append(d)
        return results

    def get_signature_count(self) -> int:
        with self._get_connection() as conn:
            return conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]

    def get_all_signatures(self) -> list[dict]:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM signatures ORDER BY category, name"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_scan_history(self) -> list[dict]:
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT
                    scan_id,
                    MIN(scan_timestamp) AS scan_timestamp,
                    COUNT(*) AS file_count,
                    SUM(anomaly_flag) AS anomaly_count,
                    MAX(CASE risk_level
                        WHEN 'CRITICAL' THEN 4
                        WHEN 'HIGH'     THEN 3
                        WHEN 'MEDIUM'   THEN 2
                        WHEN 'LOW'      THEN 1
                        ELSE 0 END) AS risk_rank
                FROM scan_results
                GROUP BY scan_id
                ORDER BY scan_timestamp DESC
            """).fetchall()
        history = []
        rank_map = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "UNKNOWN"}
        for row in rows:
            d = dict(row)
            d["highest_risk"] = rank_map.get(d.pop("risk_rank", 0), "UNKNOWN")
            history.append(d)
        return history

    def export_json(self, scan_id: str, output_path: str) -> None:
        results = self.get_scan_results(scan_id)
        export_json(results, scan_id, output_path)

    def export_csv(self, scan_id: str, output_path: str) -> None:
        results = self.get_scan_results(scan_id)
        export_csv(results, scan_id, output_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _match_signature(self, header_bytes: bytes, declared_ext: str = "") -> dict | None:
        """
        Longest-match-wins strategy with extension-aware disambiguation.

        Handles known ambiguous magic bytes:
          - CA FE BA BE: Java .class vs Mach-O Fat Binary — use extension hint
          - 50 4B 03 04: ZIP container shared by DOCX/XLSX/PPTX/JAR/APK — use extension hint
        """
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM signatures ORDER BY LENGTH(header_hex) DESC"
            ).fetchall()

        candidates = []
        for row in rows:
            sig = dict(row)
            try:
                sig_bytes = bytes(
                    int(h, 16) for h in sig["header_hex"].split()
                    if h.lower() != "xx"
                )
                if header_bytes[:len(sig_bytes)] == sig_bytes:
                    candidates.append((len(sig_bytes), sig))
            except (ValueError, TypeError):
                continue

        if not candidates:
            return None

        # Sort: longest match first
        candidates.sort(key=lambda x: x[0], reverse=True)
        best_len = candidates[0][0]
        top = [sig for length, sig in candidates if length == best_len]

        if len(top) == 1:
            return top[0]

        # Multiple signatures share the same header length — disambiguate by extension
        if declared_ext:
            ext_lower = declared_ext.lower()
            for sig in top:
                try:
                    exts = json.loads(sig["extensions"])
                    if ext_lower in [e.lower() for e in exts]:
                        return sig
                except Exception:
                    pass

        # Return highest-risk match when no extension hint resolves it
        risk_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
        top.sort(key=lambda s: risk_rank.get(s["risk_level"], 0), reverse=True)
        return top[0]

    def _compute_hashes(self, filepath: str) -> tuple[str, str]:
        return compute_hashes(filepath)

    def _extract_hex_preview(self, filepath: str, num_bytes: int = 64) -> list[dict]:
        return extract_hex_preview(filepath, num_bytes)

    def _detect_anomaly(
        self, detected_category: str, declared_ext: str, mime_type: str
    ) -> tuple[bool, str]:
        for cat, suspicious_exts, reason, _ in ANOMALY_RULES:
            if detected_category == cat and declared_ext in suspicious_exts:
                return True, reason
        return False, ""

    def _verify_footer(self, filepath: str, footer_hex: str | None) -> bool | None:
        if not footer_hex:
            return None
        try:
            footer_bytes = bytes(int(h, 16) for h in footer_hex.split())
            size = len(footer_bytes)
            with open(filepath, 'rb') as f:
                f.seek(-size, 2)
                tail = f.read(size)
            return tail == footer_bytes
        except (OSError, ValueError):
            return None

    def _compute_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = collections.Counter(data)
        length = len(data)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    def _yara_lite_scan(self, filepath: str) -> list[dict]:
        hits = []
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            for pattern in SUSPICIOUS_STRINGS:
                offset = data.find(pattern)
                if offset != -1:
                    hits.append({
                        "pattern": pattern.decode('utf-8', errors='replace'),
                        "offset": hex(offset),
                    })
        except (OSError, PermissionError):
            pass
        return hits

    def _persist_result(self, result: dict) -> None:
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO scan_results (
                        scan_id, filename, filepath, detected_type, mime_type,
                        declared_ext, risk_level, anomaly_flag, anomaly_reason,
                        md5_hash, sha256_hash, file_size, scan_timestamp,
                        footer_valid, hex_preview, error
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    result["scan_id"],
                    result["filename"],
                    result["filepath"],
                    result["detected_type"],
                    result["mime_type"],
                    result["declared_ext"],
                    result["risk_level"],
                    int(result["anomaly_flag"]),
                    result["anomaly_reason"],
                    result["md5_hash"],
                    result["sha256_hash"],
                    result["file_size"],
                    result["scan_timestamp"],
                    None if result["footer_valid"] is None else int(result["footer_valid"]),
                    json.dumps(result["hex_preview"]),
                    result["error"],
                ))
        except Exception as e:
            logger.error("Failed to persist result for %s: %s", result.get("filepath"), e)