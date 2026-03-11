# CSRF 토큰 탐지를 위한 키워드 목록
CSRF_TOKEN_KEYWORDS = (
    "csrf", "token", "nonce", "_token",
    "authenticity_token", "csrf_token",
    "_verify", "xsrf", "anti-forgery", "xsrf-token",
)
# <meta> 태그 CSRF 토큰 name 속성 키워드
META_CSRF_NAMES = (
    "csrf-token", "csrf-param", "csrf_token",
    "xsrf-token", "_csrf", "anti-forgery-token",
    "request-verification-token",
)
# <script> 내 전역 JS 변수 CSRF 토큰 탐지 regex
# Matches: csrfToken = "value", window.csrf_token = 'value', var XSRF_TOKEN: "value"
JS_TOKEN_PATTERN = (
    r"""(?:csrf[_-]?token|csrftoken|xsrf[_-]?token|anti[_-]?forgery[_-]?token|"""
    r"""authenticity[_-]?token|request[_-]?verification[_-]?token)"""
    r"""\s*[:=]\s*["']([^"']{8,})["']"""
)
# SameSite 쿠키 보안 값
SAMESITE_SECURE_VALUES = ("strict", "lax")
# 요청 타임아웃 설정 (초)
DEFAULT_TIMEOUT = 10
# User-Agent 헤더 값 설정
USER_AGENT = "s2n_csrf/1.0 (CSRF Scanner)"
