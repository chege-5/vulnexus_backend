from __future__ import annotations

import zipfile
from uuid import uuid4

import pytest

from app.services.models.pipeline import ScanContext, ScanTarget
from app.services.scanners.secrets import SASTScanner
from app.utils.file_utils import extract_zip, validate_zip_archive


def test_zip_validation_and_extraction_keep_every_supported_file(tmp_path):
    archive = tmp_path / "project.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("src/auth.py", "import hashlib\nhashlib.md5(b'data')\n")
        zf.writestr("config/settings.yaml", "debug: true\n")
        zf.writestr("assets/logo.png", b"not source")
        zf.writestr("../outside.py", "should not escape")

    assert validate_zip_archive(str(archive))["source_file_count"] == 2

    destination = tmp_path / "extracted"
    destination.mkdir()
    extracted = extract_zip(str(archive), str(destination))

    assert {path.replace("\\", "/").split("/extracted/")[-1] for path in extracted} == {
        "src/auth.py",
        "config/settings.yaml",
    }
    assert not (tmp_path / "outside.py").exists()


def test_zip_validation_rejects_empty_or_invalid_archives(tmp_path):
    empty_archive = tmp_path / "empty.zip"
    with zipfile.ZipFile(empty_archive, "w") as zf:
        zf.writestr("assets/logo.png", b"not source")

    with pytest.raises(ValueError, match="supported source"):
        validate_zip_archive(str(empty_archive))

    invalid_archive = tmp_path / "invalid.zip"
    invalid_archive.write_bytes(b"not a zip archive")
    with pytest.raises(ValueError, match="valid ZIP"):
        validate_zip_archive(str(invalid_archive))


@pytest.mark.asyncio
async def test_sast_scans_every_extracted_file_and_reports_archive_relative_paths(tmp_path):
    first = tmp_path / "src" / "legacy.py"
    first.parent.mkdir()
    first.write_text("import hashlib\nhashlib.md5(b'data')\n")
    second = tmp_path / "src" / "randomness.py"
    second.write_text("import random\nnonce = random.random()\n")

    source_files = [str(first), str(second)]
    context = ScanContext(
        scan_id=uuid4(),
        scan_type="file",
        target=ScanTarget(kind="file", value="project.zip"),
        source_path=str(tmp_path),
        options={
            "source_files": source_files,
            "source_file_display_paths": {
                str(first): "src/legacy.py",
                str(second): "src/randomness.py",
            },
        },
    )

    result = await SASTScanner().scan(context.target, context)

    assert result.metadata["files_scanned"] == 2
    assert any(finding.location == "src/legacy.py:2" for finding in result.findings)
    assert any(finding.location == "src/randomness.py:2" for finding in result.findings)
    assert all(str(tmp_path) not in (finding.location or "") for finding in result.findings)
