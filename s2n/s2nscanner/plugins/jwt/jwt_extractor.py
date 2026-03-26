"""JWT 토큰 추출기 - HTTP 컨텍스트의 여러 위치에서 JWT를 추출합니다."""
import re
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from s2n.s2nscanner.interfaces import PluginContext

# JWT 토큰 패턴: eyJ로 시작하는 세 파트 (마지막 서명은 비어있을 수 있음)
JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
)


class JWTExtractor:
    """HTTP 요청/응답의 여러 위치에서 JWT를 추출합니다."""

    def extract_from_context(self, plugin_context: "PluginContext") -> List[str]:
        """AuthConfig, HttpClient 세션 헤더/쿠키에서 JWT를 탐색합니다.

        Returns:
            중복 없는 raw JWT 토큰 문자열 목록
        """
        tokens: List[str] = []
        seen: set = set()

        def _add(t: str) -> None:
            t = t.strip()
            if t and t not in seen:
                seen.add(t)
                tokens.append(t)

        scan_context = getattr(plugin_context, "scan_context", None)
        if not scan_context:
            return tokens

        # 1. AuthConfig.token (auth_type=BEARER)
        config = getattr(scan_context, "config", None)
        if config:
            auth_config = getattr(config, "auth_config", None)
            if auth_config:
                # Bearer 토큰
                token_val = getattr(auth_config, "token", None)
                if token_val:
                    # "Bearer eyJ..." 형태에서 JWT 추출
                    for match in JWT_PATTERN.finditer(str(token_val)):
                        _add(match.group())

                # Authorization 헤더에 포함된 경우
                headers = getattr(auth_config, "headers", {}) or {}
                for header_name, header_val in headers.items():
                    if isinstance(header_val, str):
                        for match in JWT_PATTERN.finditer(header_val):
                            _add(match.group())

                # 쿠키에 포함된 경우
                cookies = getattr(auth_config, "cookies", {}) or {}
                for cookie_val in cookies.values():
                    if isinstance(cookie_val, str):
                        for match in JWT_PATTERN.finditer(cookie_val):
                            _add(match.group())

        # 2. HttpClient 세션 헤더 및 쿠키
        http_client = getattr(scan_context, "http_client", None)
        if http_client:
            session = getattr(http_client, "s", None)
            if session:
                # 세션 헤더 (Authorization: Bearer <jwt>)
                session_headers = dict(getattr(session, "headers", {}) or {})
                for header_name, header_val in session_headers.items():
                    if isinstance(header_val, str):
                        for match in JWT_PATTERN.finditer(header_val):
                            _add(match.group())

                # 세션 쿠키
                session_cookies = getattr(session, "cookies", None)
                if session_cookies:
                    try:
                        for cookie in session_cookies:
                            val = getattr(cookie, "value", None) or str(cookie)
                            for match in JWT_PATTERN.finditer(val):
                                _add(match.group())
                    except Exception:
                        pass

        return tokens
