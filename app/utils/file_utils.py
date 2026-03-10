import os
import uuid
import zipfile
import shutil
from pathlib import Path
from fastapi import UploadFile
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

ALLOWED_EXTENSIONS = {
    ".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".cs", ".go", ".rb",
    ".rs", ".php", ".swift", ".kt", ".scala", ".r", ".m", ".mm",
    ".pem", ".key", ".crt", ".cer", ".der", ".p12", ".pfx",
    ".conf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".xml", ".toml",
    ".zip",
}

MAX_SIZE = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024


def validate_upload(file: UploadFile) -> bool:
    if file.filename is None:
        return False
    ext = Path(file.filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS


async def save_upload(file: UploadFile, scan_id: uuid.UUID) -> str:
    scan_dir = os.path.join(settings.UPLOAD_DIR, str(scan_id))
    os.makedirs(scan_dir, exist_ok=True)
    safe_name = Path(file.filename).name if file.filename else "upload"
    dest = os.path.join(scan_dir, safe_name)
    size = 0
    with open(dest, "wb") as f:
        while chunk := await file.read(8192):
            size += len(chunk)
            if size > MAX_SIZE:
                os.remove(dest)
                raise ValueError(f"File exceeds {settings.MAX_UPLOAD_SIZE_MB}MB limit")
            f.write(chunk)
    return dest


def extract_zip(zip_path: str, dest_dir: str) -> list[str]:
    max_entries = settings.MAX_ZIP_ENTRIES
    max_uncompressed = settings.MAX_ZIP_UNCOMPRESSED_MB * 1024 * 1024
    max_ratio = settings.MAX_ZIP_RATIO

    extracted = []
    total_uncompressed = 0

    with zipfile.ZipFile(zip_path, "r") as zf:
        entries = [i for i in zf.infolist() if not i.is_dir()]
        if len(entries) > max_entries:
            raise ValueError(f"ZIP contains {len(entries)} entries, exceeding limit of {max_entries}")

        for info in entries:
            total_uncompressed += info.file_size
            if total_uncompressed > max_uncompressed:
                raise ValueError(
                    f"ZIP uncompressed size exceeds {settings.MAX_ZIP_UNCOMPRESSED_MB}MB limit"
                )
            if info.compress_size > 0 and info.file_size / info.compress_size > max_ratio:
                raise ValueError(
                    f"ZIP entry {info.filename} has suspicious compression ratio "
                    f"({info.file_size / info.compress_size:.0f}x), possible zip bomb"
                )

            safe = _sanitize_zip_path(info.filename)
            if safe is None:
                continue
            target = os.path.join(dest_dir, safe)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            extracted.append(target)
    return extracted


def _sanitize_zip_path(member_path: str) -> str | None:
    clean = os.path.normpath(member_path)
    if clean.startswith("..") or os.path.isabs(clean):
        logger.warning(f"Skipping suspicious zip member: {member_path}")
        return None
    return clean


def collect_source_files(directory: str) -> list[str]:
    files = []
    for root, _, filenames in os.walk(directory):
        for fn in filenames:
            ext = Path(fn).suffix.lower()
            if ext in ALLOWED_EXTENSIONS and ext != ".zip":
                files.append(os.path.join(root, fn))
    return files


def cleanup_scan_dir(scan_id: uuid.UUID):
    scan_dir = os.path.join(settings.UPLOAD_DIR, str(scan_id))
    if os.path.exists(scan_dir):
        shutil.rmtree(scan_dir, ignore_errors=True)
