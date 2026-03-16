"""
s2nscanner 공용 상수
- 여러 모듈에서 공통으로 사용하는 상수를 중앙 관리
- 플러그인 전용 상수는 각 플러그인의 constants 파일에 유지
"""

# ============================================================================
# CSRF 토큰 탐지
# ============================================================================

# hidden input name 매칭 키워드
CSRF_TOKEN_KEYWORDS = (
    "csrf", "token", "nonce", "_token",
    "authenticity_token", "csrf_token",
    "_verify", "xsrf", "anti-forgery", "xsrf-token",
)

# <meta> 태그 name 속성 키워드
META_CSRF_NAMES = (
    "csrf-token", "csrf-param", "csrf_token",
    "xsrf-token", "_csrf", "anti-forgery-token",
    "request-verification-token",
)

# <script> 내 전역 JS 변수 CSRF 토큰 탐지 regex
JS_TOKEN_PATTERN = (
    r"""(?:csrf[_-]?token|csrftoken|xsrf[_-]?token|anti[_-]?forgery[_-]?token|"""
    r"""authenticity[_-]?token|request[_-]?verification[_-]?token)"""
    r"""\s*[:=]\s*["']([^"']{8,})["']"""
)

# ============================================================================
# HTML 폼 필드 타입
# ============================================================================

FIELD_TYPE_HIDDEN = "hidden"
FIELD_TYPE_PASSWORD = "password"
FIELD_TYPE_TEXT = "text"
FIELD_TYPE_EMAIL = "email"
FIELD_TYPE_FILE = "file"
FIELD_TYPE_SUBMIT = "submit"
FIELD_TYPE_URL = "url"
FIELD_TYPE_NUMBER = "number"
FIELD_TYPE_TEL = "tel"
FIELD_TYPE_TEXTAREA = "textarea"

# 사용자 입력 가능 필드 타입 (XSS/SQLi 등 인젝션 대상)
INPUT_FIELD_TYPES = (FIELD_TYPE_TEXT, FIELD_TYPE_EMAIL, FIELD_TYPE_URL, FIELD_TYPE_NUMBER, FIELD_TYPE_TEL)

# 폼 데이터 구성 시 제외할 필드 타입 (username 필드 자동 탐색 시)
NON_INPUT_FIELD_TYPES = (FIELD_TYPE_HIDDEN, FIELD_TYPE_PASSWORD, FIELD_TYPE_SUBMIT, FIELD_TYPE_FILE)

# ============================================================================
# 타임아웃 (초)
# ============================================================================

DEFAULT_TIMEOUT = 10
CRAWL_TIMEOUT = 5
AUTH_TIMEOUT = 5
AUTH_POST_TIMEOUT = 10

# ============================================================================
# 링크 추출 대상 태그/속성 쌍
# ============================================================================

LINK_TAG_ATTRS = [
    ("a", "href"),
    ("form", "action"),
    ("script", "src"),
    ("iframe", "src"),
    ("link", "href"),
]
