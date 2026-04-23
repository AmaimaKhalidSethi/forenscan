"""Cryptographic hashing — streaming MD5 + SHA-256."""
import hashlib
from config import CHUNK_SIZE


def compute_hashes(filepath: str) -> tuple[str, str]:
    """
    Streaming MD5 + SHA-256 — memory-safe for large files.
    Returns (md5_hex, sha256_hex).
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()