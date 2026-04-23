import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.path.join(BASE_DIR, "forensic_signatures.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50MB
MAX_FILE_SIZE_SCAN = 500 * 1024 * 1024  # 500MB — skip larger in dir scan
MAX_DIR_FILES = 500

CHUNK_SIZE = 65536  # 64KB

ALLOWED_SCAN_ROOTS = [
    os.path.join(BASE_DIR, "evidence"),
    "/tmp/forensic_evidence",
]

BLOCKED_UPLOAD_EXTENSIONS = {'.php', '.py', '.rb', '.sh', '.pl', '.cgi', '.asp', '.aspx', '.exe', '.bat', '.cmd', '.ps1'}

FORENSCAN_VERSION = "1.0"