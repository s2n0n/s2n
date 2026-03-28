"""JWTExtractor 단위 테스트"""
import pytest
from types import SimpleNamespace

from s2n.s2nscanner.plugins.jwt.jwt_extractor import JWTExtractor, JWT_PATTERN

# ── 테스트용 실제 JWT 토큰 ──────────────────────────────────────────────────
# header: {"alg":"HS256","typ":"JWT"}, payload: {"sub":"1234","role":"user"}
# secret: 'secret'
VALID_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0Iiwicm9sZSI6InVzZXIifQ"
    ".placeholder_sig"
)

# header: {"alg":"none","typ":"JWT"}
NONE_ALG_JWT = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
    ".eyJzdWIiOiIxMjM0In0"
    "."
)


def _make_context(token: str = None, cookie_token: str = None, header_token: str = None):
    """테스트용 PluginContext Namespace를 생성합니다."""
    auth_config = SimpleNamespace(
        token=token,
        headers={"Authorization": f"Bearer {header_token}"} if header_token else {},
        cookies={"access_token": cookie_token} if cookie_token else {},
    )
    config = SimpleNamespace(auth_config=auth_config)
    session = SimpleNamespace(
        headers={"Authorization": f"Bearer {header_token}"} if header_token else {},
        cookies=[],
    )
    http_client = SimpleNamespace(s=session)
    scan_context = SimpleNamespace(config=config, http_client=http_client)
    return SimpleNamespace(scan_context=scan_context)


class TestJWTPattern:
    def test_matches_valid_jwt(self):
        assert JWT_PATTERN.search(VALID_JWT) is not None

    def test_matches_none_alg_jwt(self):
        assert JWT_PATTERN.search(NONE_ALG_JWT) is not None

    def test_no_match_for_plain_string(self):
        assert JWT_PATTERN.search("hello world") is None

    def test_no_match_for_base64_without_dots(self):
        assert JWT_PATTERN.search("eyJhbGciOiJIUzI1NiJ9") is None

    def test_matches_jwt_inside_bearer(self):
        bearer = f"Bearer {VALID_JWT}"
        match = JWT_PATTERN.search(bearer)
        assert match is not None
        assert match.group() == VALID_JWT


class TestJWTExtractor:
    def setup_method(self):
        self.extractor = JWTExtractor()

    def test_extract_from_auth_config_token(self):
        ctx = _make_context(token=VALID_JWT)
        tokens = self.extractor.extract_from_context(ctx)
        assert VALID_JWT in tokens

    def test_extract_from_auth_config_bearer_string(self):
        ctx = _make_context(token=f"Bearer {VALID_JWT}")
        tokens = self.extractor.extract_from_context(ctx)
        assert VALID_JWT in tokens

    def test_extract_from_auth_header(self):
        ctx = _make_context(header_token=VALID_JWT)
        tokens = self.extractor.extract_from_context(ctx)
        assert VALID_JWT in tokens

    def test_extract_from_cookie(self):
        ctx = _make_context(cookie_token=VALID_JWT)
        tokens = self.extractor.extract_from_context(ctx)
        assert VALID_JWT in tokens

    def test_no_duplicates(self):
        """같은 토큰이 여러 위치에 있어도 중복 없이 반환."""
        ctx = _make_context(token=VALID_JWT, header_token=VALID_JWT)
        tokens = self.extractor.extract_from_context(ctx)
        assert tokens.count(VALID_JWT) == 1

    def test_empty_when_no_jwt(self):
        ctx = _make_context(token=None)
        tokens = self.extractor.extract_from_context(ctx)
        assert tokens == []

    def test_empty_when_no_scan_context(self):
        ctx = SimpleNamespace()  # scan_context 없음
        tokens = self.extractor.extract_from_context(ctx)
        assert tokens == []

    def test_empty_when_no_auth_config(self):
        config = SimpleNamespace(auth_config=None)
        scan_context = SimpleNamespace(config=config, http_client=None)
        ctx = SimpleNamespace(scan_context=scan_context)
        tokens = self.extractor.extract_from_context(ctx)
        assert tokens == []

    def test_multiple_tokens_in_different_locations(self):
        """서로 다른 위치에 서로 다른 토큰이 있으면 모두 추출."""
        ctx = _make_context(token=VALID_JWT, cookie_token=NONE_ALG_JWT)
        tokens = self.extractor.extract_from_context(ctx)
        assert VALID_JWT in tokens
        assert NONE_ALG_JWT in tokens
        assert len(tokens) == 2
