from __future__ import annotations
import re
import urllib.parse
from collections import deque
from typing import List
from s2n.s2nscanner.logger import get_logger

logger = get_logger("crawler")

# 링크 추출 대상 태그/속성 쌍
_LINK_TAG_ATTRS = [
    ("a", "href"), ("form", "action"),
    ("script", "src"), ("iframe", "src"),
    ("link", "href"),
]


def extract_same_origin_links(html: str, page_url: str, base_netloc: str) -> List[str]:
    """HTML에서 같은 오리진의 링크를 추출해 절대 URL 리스트로 반환."""
    links: List[str] = []
    for tag, attr in _LINK_TAG_ATTRS:
        for m in re.finditer(fr"<{tag}[^>]+{attr}=['\"]([^'\"]+)['\"]", html, re.I):
            link = m.group(1)
            if not link:
                continue
            if link.startswith(("mailto:", "javascript:")):
                continue
            full = urllib.parse.urljoin(page_url, link)
            parsed = urllib.parse.urlparse(full)
            if parsed.netloc == base_netloc:
                links.append(full)
    return links


def crawl_recursive(base_url: str, client, depth: int = 2, timeout: int = 5) -> List[str]:
    visited = set()
    to_visit = deque([(base_url, 0)])
    found_links = []

    parsed_base = urllib.parse.urlparse(base_url)

    while to_visit:
        url, d = to_visit.popleft()
        if d > depth or url in visited:
            continue
        visited.add(url)

        try:
            resp = client.get(url, timeout=timeout)
            html = resp.text or ""
        except Exception:
            logger.debug("crawl: failed to GET %s", url, exc_info=True)
            continue

        found_links.append(url)

        for full in extract_same_origin_links(html, url, parsed_base.netloc):
            if full not in visited:
                to_visit.append((full, d + 1))

    return list(dict.fromkeys(found_links))