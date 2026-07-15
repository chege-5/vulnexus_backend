import csv
from zipfile import ZipFile

from app.services.report_generator import generate_csv_report, generate_docx_report


def test_csv_export_neutralizes_formula_cells(tmp_path):
    output_path = tmp_path / "report.csv"
    payload = {
        "vulnerabilities": [
            {
                "description": "=HYPERLINK(\"https://example.invalid\",\"click\")",
                "severity": "High",
                "confidence": 0.9,
                "ml_score": 80,
                "display_evidence": "@SUM(1,1)",
            }
        ]
    }

    generate_csv_report(payload, str(output_path))

    with output_path.open(newline="", encoding="utf-8") as handle:
        row = next(csv.DictReader(handle))
    assert row["description"].startswith("'=")
    assert row["evidence"].startswith("'@")


def test_docx_export_contains_structured_report_parts(tmp_path):
    output_path = tmp_path / "report.docx"
    generate_docx_report(
        {
            "target": "https://example.com",
            "overall_score": 72,
            "overall_verdict": "High",
            "severity_counts": {"High": 1},
            "vulnerability_count": 1,
            "vulnerabilities": [
                {
                    "display_title": "Weak TLS Configuration",
                    "severity": "High",
                    "description": "TLS posture needs remediation.",
                    "display_evidence": "TLS 1.0 supported",
                    "remediation": "Disable TLS 1.0 and enable TLS 1.2+.",
                }
            ],
        },
        str(output_path),
    )

    with ZipFile(output_path) as archive:
        document = archive.read("word/document.xml").decode("utf-8")
    assert "VulNexus Security Report" in document
    assert "Risk Distribution" in document
    assert "Weak TLS Configuration" in document
    assert "Verification:" in document
