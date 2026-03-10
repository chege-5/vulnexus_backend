import httpx
from typing import Optional
from app.config import settings
from app.utils.cache import cache
from app.utils.logger import get_logger

logger = get_logger(__name__)

KEYWORD_MAP = {
    "MD5": ["CVE-2004-2761", "CVE-2008-5077"],
    "SHA1": ["CVE-2005-4900", "CVE-2017-15906"],
    "DES": ["CVE-2016-2183", "CVE-2012-5371"],
    "RC2": ["CVE-2015-2808"],
    "AES-ECB": ["CVE-2014-3566"],
    "RSA": ["CVE-2017-13098", "CVE-2018-0737"],
    "TLSv1": ["CVE-2011-3389", "CVE-2014-3566"],
    "TLSv1.0": ["CVE-2011-3389", "CVE-2014-3566"],
    "TLSv1.1": ["CVE-2015-0204"],
    "self-signed": ["CVE-2014-0160"],
    "expired-cert": ["CVE-2014-0160"],
    "HARDCODED_KEY": ["CVE-2018-15473", "CVE-2019-14899"],
    "INSECURE_RANDOM": ["CVE-2008-0166"],
}


async def map_vulnerability_to_cves(vuln_keyword: str) -> list[dict]:
    cached = await cache.get("cve", vuln_keyword)
    if cached:
        return cached

    cve_ids = KEYWORD_MAP.get(vuln_keyword, [])
    results = []

    for cve_id in cve_ids:
        detail = await _fetch_cve_detail(cve_id)
        if detail:
            results.append(detail)

    if not results and vuln_keyword:
        results = await _search_nvd(vuln_keyword)

    if not results and vuln_keyword:
        results = await _search_circl(vuln_keyword)

    if results:
        await cache.set("cve", vuln_keyword, results)

    return results


async def _fetch_cve_detail(cve_id: str) -> Optional[dict]:
    cached = await cache.get("cve_detail", cve_id)
    if cached:
        return cached

    detail = await _fetch_from_mitre(cve_id)
    if not detail:
        detail = await _fetch_from_nvd(cve_id)
    if not detail:
        detail = await _fetch_from_circl(cve_id)

    if detail:
        await cache.set("cve_detail", cve_id, detail)
    return detail


async def _fetch_from_mitre(cve_id: str) -> Optional[dict]:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{settings.MITRE_CVE_API_URL}/cve/{cve_id}")
            if r.status_code == 200:
                data = r.json()
                cna = data.get("cveMetadata", {})
                containers = data.get("containers", {}).get("cna", {})
                desc_list = containers.get("descriptions", [{}])
                description = desc_list[0].get("value", "") if desc_list else ""
                return {
                    "cve_id": cve_id,
                    "summary": description[:500],
                    "cvss_score": None,
                    "published_date": cna.get("datePublished"),
                    "source": "MITRE",
                }
    except Exception as e:
        logger.debug(f"MITRE fetch failed for {cve_id}: {e}")
    return None


async def _fetch_from_nvd(cve_id: str) -> Optional[dict]:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            headers = {}
            if settings.NVD_API_KEY:
                headers["apiKey"] = settings.NVD_API_KEY
            r = await client.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
                headers=headers,
            )
            if r.status_code == 200:
                data = r.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve_data = vulns[0].get("cve", {})
                    descs = cve_data.get("descriptions", [])
                    en_desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                    metrics = cve_data.get("metrics", {})
                    cvss_v31 = metrics.get("cvssMetricV31", [{}])
                    cvss_score = cvss_v31[0].get("cvssData", {}).get("baseScore") if cvss_v31 else None
                    return {
                        "cve_id": cve_id,
                        "summary": en_desc[:500],
                        "cvss_score": cvss_score,
                        "published_date": cve_data.get("published"),
                        "source": "NVD",
                    }
    except Exception as e:
        logger.debug(f"NVD fetch failed for {cve_id}: {e}")
    return None


async def _fetch_from_circl(cve_id: str) -> Optional[dict]:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{settings.CVE_CIRCL_API_URL}/cve/{cve_id}")
            if r.status_code == 200:
                data = r.json()
                return {
                    "cve_id": cve_id,
                    "summary": (data.get("summary") or "")[:500],
                    "cvss_score": data.get("cvss"),
                    "published_date": data.get("Published"),
                    "source": "CIRCL",
                }
    except Exception as e:
        logger.debug(f"CIRCL fetch failed for {cve_id}: {e}")
    return None


async def _search_nvd(keyword: str) -> list[dict]:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            headers = {}
            if settings.NVD_API_KEY:
                headers["apiKey"] = settings.NVD_API_KEY
            r = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": keyword, "resultsPerPage": 3},
                headers=headers,
            )
            if r.status_code == 200:
                data = r.json()
                results = []
                for v in data.get("vulnerabilities", [])[:3]:
                    cve_data = v.get("cve", {})
                    descs = cve_data.get("descriptions", [])
                    en_desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                    results.append({
                        "cve_id": cve_data.get("id"),
                        "summary": en_desc[:500],
                        "cvss_score": None,
                        "published_date": cve_data.get("published"),
                        "source": "NVD",
                    })
                return results
    except Exception as e:
        logger.debug(f"NVD search failed for {keyword}: {e}")
    return []


async def _search_circl(keyword: str) -> list[dict]:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{settings.CVE_CIRCL_API_URL}/search/{keyword}")
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    return [
                        {
                            "cve_id": item.get("id"),
                            "summary": (item.get("summary") or "")[:500],
                            "cvss_score": item.get("cvss"),
                            "published_date": item.get("Published"),
                            "source": "CIRCL",
                        }
                        for item in data[:3]
                    ]
    except Exception as e:
        logger.debug(f"CIRCL search failed for {keyword}: {e}")
    return []
