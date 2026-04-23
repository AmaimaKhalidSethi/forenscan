"""JSON + CSV serialization for chain-of-custody export."""
import json
import csv
import datetime
from config import FORENSCAN_VERSION


def export_json(results: list[dict], scan_id: str, output_path: str) -> None:
    envelope = {
        "forenscan_version": FORENSCAN_VERSION,
        "export_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "scan_id": scan_id,
        "results": results,
        "chain_of_custody": {
            "analyst": "automated",
            "tool": "ForenScan",
            "hash_algorithm": "MD5+SHA256",
        },
    }
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(envelope, f, indent=2, default=str)


CSV_COLUMNS = [
    "scan_id", "filename", "filepath", "detected_type", "mime_type",
    "declared_ext", "risk_level", "anomaly_flag", "anomaly_reason",
    "md5_hash", "sha256_hash", "file_size", "scan_timestamp", "footer_valid",
]


def export_csv(results: list[dict], scan_id: str, output_path: str) -> None:
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction='ignore')
        writer.writeheader()
        for row in results:
            row_out = {col: row.get(col, '') for col in CSV_COLUMNS}
            row_out['scan_id'] = scan_id
            writer.writerow(row_out)