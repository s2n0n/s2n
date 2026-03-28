"""
autobot_detector.py
Selenium WebDriver 응답을 분석해 봇 차단 여부를 판정한다.

판정 우선순위 (하나라도 해당하면 was_blocked=True):
  1. HTTP 429 / 403 응답
  2. 응답 본문에 CAPTCHA 키워드 포함
  3. 현재 도메인이 원본 도메인과 다름 (리디렉트 차단 페이지)
  4. document.title 또는 window.location에서 차단 페이지 패턴 감지
"""

import re
from typing import Tuple
from urllib.parse import urlparse

from selenium.webdriver.remote.webdriver import WebDriver


# 차단 페이지에서 자주 등장하는 키워드
_CAPTCHA_KEYWORDS = [
    "recaptcha",
    "hcaptcha",
    "captcha",
    "robot",
    "automated",
    "bot detected",
    "access denied",
    "ddos-guard",
    "cloudflare",
    "challenge",
    "verify you are human",
]

# document.title에서 차단 패턴 감지용 정규식
_BLOCK_TITLE_PATTERNS = re.compile(
    r"(access denied|attention required|just a moment|blocked|403|429|forbidden|robot|captcha)",
    re.IGNORECASE,
)


def _get_page_source_lower(driver: WebDriver) -> str:
    try:
        return driver.page_source.lower()
    except Exception:
        return ""


def _get_current_url(driver: WebDriver) -> str:
    try:
        return driver.current_url
    except Exception:
        return ""


def _get_title(driver: WebDriver) -> str:
    try:
        return driver.title or ""
    except Exception:
        return ""


def _check_http_status(driver: WebDriver) -> Tuple[bool, str]:
    """
    JavaScript performance.getEntriesByType('navigation')으로
    HTTP 상태 코드를 가져와 403/429 여부를 검사한다.
    """
    try:
        status = driver.execute_script(
            "var e = performance.getEntriesByType('navigation'); "
            "return e.length > 0 ? e[0].responseStatus : null;"
        )
        if status in (403, 429):
            return True, f"HTTP {status} 응답"
    except Exception:
        pass
    return False, ""


def _check_captcha_keywords(page_source: str) -> Tuple[bool, str]:
    """응답 본문에 CAPTCHA 관련 키워드가 있으면 차단으로 판정."""
    for kw in _CAPTCHA_KEYWORDS:
        if kw in page_source:
            return True, f"CAPTCHA/봇 차단 키워드 감지: '{kw}'"
    return False, ""


def _check_domain_redirect(driver: WebDriver, original_url: str) -> Tuple[bool, str]:
    """현재 URL의 도메인이 원본 도메인과 다르면 차단 리디렉트로 판정."""
    try:
        current_url = _get_current_url(driver)
        original_host = urlparse(original_url).netloc
        current_host = urlparse(current_url).netloc
        if original_host and current_host and original_host != current_host:
            return True, f"도메인 리디렉트 감지: {original_host} → {current_host}"
    except Exception:
        pass
    return False, ""


def _check_block_title(driver: WebDriver) -> Tuple[bool, str]:
    """document.title 또는 window.location에서 차단 패턴을 검사."""
    title = _get_title(driver)
    if _BLOCK_TITLE_PATTERNS.search(title):
        return True, f"차단 페이지 타이틀 감지: '{title}'"
    return False, ""


def is_blocked(driver: WebDriver, original_url: str = "") -> Tuple[bool, str]:
    """
    WebDriver 현재 상태를 분석해 봇 차단 여부를 반환.

    Args:
        driver: 현재 페이지가 로드된 WebDriver
        original_url: 리디렉트 감지를 위한 원본 URL (선택)

    Returns:
        (was_blocked: bool, reason: str)
    """
    # 우선순위 1: HTTP 상태 코드
    blocked, reason = _check_http_status(driver)
    if blocked:
        return True, reason

    page_source = _get_page_source_lower(driver)

    # 우선순위 2: CAPTCHA 키워드
    blocked, reason = _check_captcha_keywords(page_source)
    if blocked:
        return True, reason

    # 우선순위 3: 도메인 리디렉트
    if original_url:
        blocked, reason = _check_domain_redirect(driver, original_url)
        if blocked:
            return True, reason

    # 우선순위 4: 차단 페이지 타이틀
    blocked, reason = _check_block_title(driver)
    if blocked:
        return True, reason

    return False, "차단 신호 없음"


def get_evidence_snippet(driver: WebDriver, max_length: int = 500) -> str:
    """
    Finding evidence 용 응답 본문 스니펫을 반환.
    본문이 없으면 URL과 title을 조합한다.
    """
    try:
        source = driver.page_source
        snippet = source[:max_length].replace("\n", " ").strip()
        return snippet if snippet else f"URL: {driver.current_url}, Title: {driver.title}"
    except Exception:
        return "응답 스니펫 추출 실패"
