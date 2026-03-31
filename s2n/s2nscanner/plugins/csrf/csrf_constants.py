"""
CSRF 플러그인 상수 — 공용 상수는 constants.py에서 가져오고 플러그인 전용만 여기에 유지
"""

# 공용 상수 re-export (기존 import 호환)
from s2n.s2nscanner.constants import (
    CSRF_TOKEN_KEYWORDS,
    META_CSRF_NAMES,
    JS_TOKEN_PATTERN,
    DEFAULT_TIMEOUT,
)

# CSRF 플러그인 전용 상수
SAMESITE_SECURE_VALUES = ("strict", "lax")
USER_AGENT = "s2n_csrf/1.0 (CSRF Scanner)"
