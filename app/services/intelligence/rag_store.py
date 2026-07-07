from __future__ import annotations

"""Small local retrieval store used to ground explanations with curated references."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class KnowledgeDocument:
    doc_id: str
    title: str
    source: str
    url: str
    tags: tuple[str, ...]
    content: str


_DOCUMENTS = [
    KnowledgeDocument(
        doc_id="owasp-csp",
        title="OWASP Content Security Policy guidance",
        source="OWASP",
        url="https://cheatsheetseries.owasp.org/",
        tags=("csp", "browser", "headers", "xss", "owasp"),
        content="Restrictive CSP reduces script injection impact and should be paired with secure defaults for headers and navigation policy.",
    ),
    KnowledgeDocument(
        doc_id="mitre-attack",
        title="MITRE ATT&CK knowledge",
        source="MITRE",
        url="https://attack.mitre.org/",
        tags=("mitre", "attack", "capec", "lateral movement", "persistence"),
        content="MITRE ATT&CK techniques describe adversary behaviors such as exploitation, persistence, privilege escalation, and exfiltration.",
    ),
    KnowledgeDocument(
        doc_id="nvd-cve",
        title="NVD vulnerability intelligence",
        source="NVD",
        url="https://nvd.nist.gov/",
        tags=("cve", "cvss", "nvd", "epss", "kev"),
        content="NVD records CVE metadata, CVSS scoring, and vendor references for software vulnerabilities.",
    ),
    KnowledgeDocument(
        doc_id="cwe-capec",
        title="CWE and CAPEC mapping",
        source="CWE/CAPEC",
        url="https://cwe.mitre.org/",
        tags=("cwe", "capec", "attack path", "weakness"),
        content="CWE captures the root weakness class while CAPEC models how attackers can exploit it in practice.",
    ),
    KnowledgeDocument(
        doc_id="vendor-advisory",
        title="Vendor advisory workflow",
        source="Vendor guidance",
        url="https://www.first.org/cvss/",
        tags=("vendor", "advisory", "patch", "mitigation"),
        content="Vendor advisories and patch notes should be used to validate the affected versions, fixes, and rollback steps.",
    ),
]


class LocalKnowledgeStore:
    def retrieve(self, query: str, *, topics: list[str] | None = None, limit: int = 5) -> list[dict[str, Any]]:
        terms = {token for token in (query or "").lower().replace("/", " ").replace("_", " ").split() if token}
        if topics:
            terms.update(topic.lower() for topic in topics if topic)

        scored: list[tuple[int, KnowledgeDocument]] = []
        for document in _DOCUMENTS:
            haystack = " ".join((document.title, document.source, document.content, " ".join(document.tags))).lower()
            score = sum(2 for term in terms if term in haystack)
            if score:
                scored.append((score, document))

        scored.sort(key=lambda item: (item[0], item[1].title), reverse=True)
        return [
            {
                "doc_id": document.doc_id,
                "title": document.title,
                "source": document.source,
                "url": document.url,
                "content": document.content,
                "tags": list(document.tags),
            }
            for _, document in scored[:limit]
        ]


knowledge_store = LocalKnowledgeStore()
