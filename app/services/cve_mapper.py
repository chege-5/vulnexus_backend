from typing import Optional

from app.services.intelligence.service import map_finding_intelligence
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def map_vulnerability_to_cves(vuln_keyword: str) -> list[dict]:
    result = await map_finding_intelligence(vuln_keyword)
    if not result.requires_cve_lookup:
        logger.debug("Skipping CVE lookup for non-version finding %s", vuln_keyword)
        return []
    normalized = []
    for hit in result.provider_hits:
        normalized.append({
            "cve_id": hit.get("identifier"),
            "summary": hit.get("summary"),
            "cvss_score": hit.get("cvss_score"),
            "published_date": hit.get("published_date"),
            "source": hit.get("source"),
            "references": hit.get("references") or [],
        })
    return normalized
