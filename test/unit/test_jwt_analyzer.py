"""JWTAnalyzer 단위 테스트"""
import base64
import hashlib
import hmac
import json

import pytest

from s2n.s2nscanner.plugins.jwt.jwt_analyzer import (
    JWTAnalyzer,
    JWTToken,
    _b64url_decode,
    _b64url_encode,
    _json_b64,
    _mask_value,
)
from s2n.s2nscanner.plugins.jwt.jwt_constants import ALG_NONE_VARIANTS

# ── 테스트 픽스처 ────────────────────────────────────────────────────────────


def _make_hs256_token(payload: dict, secret: str = "secret") -> str:
    """테스트용 HS256 JWT를 직접 생성합니다."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _json_b64(header)
    payload_b64 = _json_b64(payload)
    msg = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


WEAK_SECRET = "secret"
STRONG_SECRET = "this-is-a-very-long-and-random-secret-key-32b"

VALID_TOKEN_RAW = _make_hs256_token({"sub": "1234", "role": "user"}, WEAK_SECRET)
STRONG_TOKEN_RAW = _make_hs256_token({"sub": "1234", "role": "user"}, STRONG_SECRET)
SENSITIVE_TOKEN_RAW = _make_hs256_token(
    {"sub": "1", "password": "mysecretpass", "email": "admin@example.com"},
    WEAK_SECRET,
)
PRIV_TOKEN_RAW = _make_hs256_token(
    {"sub": "1", "role": "user", "admin": False},
    WEAK_SECRET,
)


class TestBase64Utils:
    def test_b64url_decode_roundtrip(self):
        original = b"hello world"
        encoded = _b64url_encode(original)
        assert _b64url_decode(encoded) == original

    def test_b64url_decode_handles_no_padding(self):
        # 패딩 없는 base64url
        encoded = base64.urlsafe_b64encode(b"test data").rstrip(b"=").decode()
        assert _b64url_decode(encoded) == b"test data"

    def test_json_b64_is_valid_base64url(self):
        obj = {"alg": "HS256", "typ": "JWT"}
        result = _json_b64(obj)
        decoded = json.loads(_b64url_decode(result))
        assert decoded == obj


class TestJWTAnalyzerParse:
    def setup_method(self):
        self.analyzer = JWTAnalyzer()

    def test_parse_valid_token(self):
        token = self.analyzer.parse(VALID_TOKEN_RAW)
        assert token is not None
        assert token.algorithm == "HS256"
        assert token.payload["sub"] == "1234"
        assert token.payload["role"] == "user"

    def test_parse_returns_none_for_invalid(self):
        assert self.analyzer.parse("not.a.valid.token.here") is None
        assert self.analyzer.parse("onlyone") is None
        assert self.analyzer.parse("a.b") is None

    def test_parse_preserves_raw(self):
        token = self.analyzer.parse(VALID_TOKEN_RAW)
        assert token.raw == VALID_TOKEN_RAW

    def test_parse_source_parameter(self):
        token = self.analyzer.parse(VALID_TOKEN_RAW, source="auth_header")
        assert token.source == "auth_header"

    def test_parse_none_alg_token(self):
        header = {"alg": "none", "typ": "JWT"}
        payload = {"sub": "1234"}
        h_b64 = _json_b64(header)
        p_b64 = _json_b64(payload)
        raw = f"{h_b64}.{p_b64}."
        token = self.analyzer.parse(raw)
        assert token is not None
        assert token.algorithm == "none"


class TestBuildNoneAlgTokens:
    def setup_method(self):
        self.analyzer = JWTAnalyzer()

    def test_returns_all_variants(self):
        token = self.analyzer.parse(VALID_TOKEN_RAW)
        none_tokens = self.analyzer.build_none_alg_tokens(token)
        assert len(none_tokens) == len(ALG_NONE_VARIANTS)

    def test_none_tokens_end_with_dot(self):
        token = self.analyzer.parse(VALID_TOKEN_RAW)
        for t in self.analyzer.build_none_alg_tokens(token):
            assert t.endswith(".")

    def test_none_tokens_have_correct_alg(self):
        token = self.analyzer.parse(VALID_TOKEN_RAW)
        none_tokens = self.analyzer.build_none_alg_tokens(token)
        for i, t in enumerate(none_tokens):
            header_part = t.split(".")[0]
            header = json.loads(_b64url_decode(header_part))
            assert header["alg"].lower() == "none"

    def test_payload_is_preserved(self):
        token = self.analyzer.parse(VALID_TOKEN_RAW)
        for none_token in self.analyzer.build_none_alg_tokens(token):
            payload_part = none_token.split(".")[1]
            payload = json.loads(_b64url_decode(payload_part))
            assert payload == token.payload


class TestCrackHS256Secret:
    def setup_method(self):
        self.analyzer = JWTAnalyzer()

    def test_cracks_weak_secret(self):
        token = self.analyzer.parse(VALID_TOKEN_RAW)
        result = self.analyzer.crack_hs256_secret(token, [WEAK_SECRET, "other"])
        assert result == WEAK_SECRET

    def test_returns_none_for_strong_secret(self):
        token = self.analyzer.parse(STRONG_TOKEN_RAW)
        result = self.analyzer.crack_hs256_secret(token, ["secret", "password", "admin"])
        assert result is None

    def test_returns_none_for_non_hs_algorithm(self):
        # RS256 토큰 시뮬레이션 (header만 변경)
        header = {"alg": "RS256", "typ": "JWT"}
        raw = f"{_json_b64(header)}.{_json_b64({'sub': '1'})}.fakesig"
        token = self.analyzer.parse(raw)
        result = self.analyzer.crack_hs256_secret(token, [WEAK_SECRET])
        assert result is None

    def test_returns_none_for_none_alg_token(self):
        h = _json_b64({"alg": "none"})
        p = _json_b64({"sub": "1"})
        token = self.analyzer.parse(f"{h}.{p}.")
        result = self.analyzer.crack_hs256_secret(token, [WEAK_SECRET])
        assert result is None


class TestSignHsToken:
    def setup_method(self):
        self.analyzer = JWTAnalyzer()

    def test_sign_and_verify(self):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "test"}
        token_str = self.analyzer.sign_hs_token(header, payload, WEAK_SECRET)
        assert token_str is not None
        # 서명 검증
        token = self.analyzer.parse(token_str)
        cracked = self.analyzer.crack_hs256_secret(token, [WEAK_SECRET])
        assert cracked == WEAK_SECRET

    def test_tampered_hs_token_uses_new_payload(self):
        token = self.analyzer.parse(VALID_TOKEN_RAW)
        new_token_str = self.analyzer.build_tampered_hs_token(
            token, WEAK_SECRET, {"role": "admin"}
        )
        assert new_token_str is not None
        new_token = self.analyzer.parse(new_token_str)
        assert new_token.payload["role"] == "admin"
        assert new_token.payload["sub"] == "1234"  # 기존 필드 유지

    def test_tampered_none_token(self):
        token = self.analyzer.parse(VALID_TOKEN_RAW)
        none_token = self.analyzer.build_tampered_none_token(token, {"admin": True})
        assert none_token.endswith(".")
        parsed = self.analyzer.parse(none_token)
        assert parsed.payload["admin"] is True


class TestFindSensitiveClaims:
    def setup_method(self):
        self.analyzer = JWTAnalyzer()

    def test_detects_password_claim(self):
        token = self.analyzer.parse(SENSITIVE_TOKEN_RAW)
        sensitive = self.analyzer.find_sensitive_claims(token)
        keys = [k for k, _ in sensitive]
        assert "password" in keys

    def test_masks_values(self):
        token = self.analyzer.parse(SENSITIVE_TOKEN_RAW)
        sensitive = self.analyzer.find_sensitive_claims(token)
        for _, masked in sensitive:
            assert "*" in masked

    def test_empty_for_safe_token(self):
        safe_token = _make_hs256_token({"sub": "1234", "iat": 1700000000})
        token = self.analyzer.parse(safe_token)
        assert self.analyzer.find_sensitive_claims(token) == []


class TestFindPrivilegeClaims:
    def setup_method(self):
        self.analyzer = JWTAnalyzer()

    def test_detects_role_claim(self):
        token = self.analyzer.parse(PRIV_TOKEN_RAW)
        priv = self.analyzer.find_privilege_claims(token)
        assert "role" in priv

    def test_detects_admin_claim(self):
        token = self.analyzer.parse(PRIV_TOKEN_RAW)
        priv = self.analyzer.find_privilege_claims(token)
        assert "admin" in priv

    def test_empty_for_no_privilege_claims(self):
        safe_token = _make_hs256_token({"sub": "1234", "name": "Alice"})
        token = self.analyzer.parse(safe_token)
        priv = self.analyzer.find_privilege_claims(token)
        assert priv == {}


class TestMaskValue:
    def test_short_value(self):
        assert _mask_value("ab") == "****"

    def test_normal_value(self):
        result = _mask_value("password123")
        assert result.startswith("pa")
        assert result.endswith("23")
        assert "*" in result

    def test_exact_4_chars(self):
        assert _mask_value("abcd") == "****"
