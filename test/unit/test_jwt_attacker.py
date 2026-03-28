"""JWTAttacker 단위 테스트 - Mock HTTP 응답 기반"""
import hashlib
import hmac
import json

import pytest
from types import SimpleNamespace

from s2n.s2nscanner.plugins.jwt.jwt_analyzer import JWTAnalyzer, _json_b64, _b64url_encode
from s2n.s2nscanner.plugins.jwt.jwt_attacker import JWTAttacker


# ── Mock HTTP 클라이언트 ─────────────────────────────────────────────────────

class _MockResponse:
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


class _CallTracker:
    """HTTP 요청 기록 + 응답 시뮬레이터"""

    def __init__(self):
        self.calls = []
        self._responses: list = []  # (matcher, response) 목록
        self._default = _MockResponse(200, '{"user":"guest"}')

    def add_response(self, matcher, response: _MockResponse):
        """matcher가 url에 대해 True이면 해당 response를 반환."""
        self._responses.append((matcher, response))

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self._dispatch(url)

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self._dispatch(url)

    def _dispatch(self, url: str) -> _MockResponse:
        headers = {}
        # 요청 헤더에서 Authorization 확인
        for _, call_url, kwargs in reversed(self.calls):
            if call_url == url:
                headers = kwargs.get("headers", {})
                break

        for matcher, response in self._responses:
            if callable(matcher) and matcher(url, headers):
                return response
            if isinstance(matcher, str) and matcher in url:
                return response
        return self._default


# ── 테스트용 JWT 생성 헬퍼 ───────────────────────────────────────────────────

def _make_hs256_token(payload: dict, secret: str = "secret") -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h_b64 = _json_b64(header)
    p_b64 = _json_b64(payload)
    msg = f"{h_b64}.{p_b64}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"


TARGET_URL = "http://target.local/api/profile"
ANALYZER = JWTAnalyzer()


def _make_token(payload=None, secret="secret"):
    p = payload or {"sub": "1234", "role": "user"}
    raw = _make_hs256_token(p, secret)
    return ANALYZER.parse(raw, source="test")


# ── JWT-01 Algorithm None ─────────────────────────────────────────────────────

class TestAttackNoneAlg:
    def test_detects_vulnerability(self):
        """none alg 토큰에 200 응답 → 취약점 탐지"""
        tracker = _CallTracker()
        # 인증 없으면 401, none alg 토큰이면 200
        def matcher(url, headers):
            auth = headers.get("Authorization", "")
            return auth == "" or auth == "Bearer "

        tracker.add_response(matcher, _MockResponse(401, "Unauthorized"))
        tracker.add_response(
            lambda url, h: "." in h.get("Authorization", "").split(" ")[-1] and
                          h.get("Authorization", "").split(" ")[-1].endswith("."),
            _MockResponse(200, '{"user":"admin"}'),
        )

        attacker = JWTAttacker(tracker, [TARGET_URL])
        token = _make_token()
        results = attacker.attack_none_alg(token)
        assert len(results) == 1
        assert results[0].attack_id == "JWT-01"
        assert results[0].success is True

    def test_no_false_positive_when_protected(self):
        """none alg 토큰에도 401 → False Positive 없음"""
        tracker = _CallTracker()
        tracker._default = _MockResponse(401, "Unauthorized")

        attacker = JWTAttacker(tracker, [TARGET_URL])
        token = _make_token()
        results = attacker.attack_none_alg(token)
        assert results == []

    def test_skip_when_no_auth_required(self):
        """인증 없이도 접근 가능한 엔드포인트면 스킵"""
        tracker = _CallTracker()
        tracker._default = _MockResponse(200, "public content")

        attacker = JWTAttacker(tracker, [TARGET_URL])
        token = _make_token()
        results = attacker.attack_none_alg(token)
        assert results == []

    def test_skip_when_no_target_url(self):
        tracker = _CallTracker()
        attacker = JWTAttacker(tracker, [])  # 빈 target_urls
        token = _make_token()
        results = attacker.attack_none_alg(token)
        assert results == []


# ── JWT-02 Weak Secret ────────────────────────────────────────────────────────

class TestAttackWeakSecret:
    def test_cracks_weak_secret(self):
        attacker = JWTAttacker(None, [TARGET_URL])
        token = _make_token(secret="secret")
        result = attacker.attack_weak_secret(token, ["password", "secret", "admin"])
        assert result == "secret"

    def test_returns_none_when_not_cracked(self):
        attacker = JWTAttacker(None, [TARGET_URL])
        token = _make_token(secret="unguessable_32byte_secret_key!!")
        result = attacker.attack_weak_secret(token, ["secret", "password"])
        assert result is None

    def test_returns_none_for_empty_secrets(self):
        attacker = JWTAttacker(None, [TARGET_URL])
        token = _make_token(secret="secret")
        result = attacker.attack_weak_secret(token, [])
        assert result is None


# ── JWT-04 Expired Token ──────────────────────────────────────────────────────

class TestAttackExpiredToken:
    def test_detects_no_exp_validation(self):
        """만료된 토큰에 200 응답 → exp 미검증 탐지"""
        tracker = _CallTracker()
        tracker._default = _MockResponse(200, '{"user":"test"}')

        attacker = JWTAttacker(tracker, [TARGET_URL])
        token = _make_token(payload={"sub": "1234", "exp": 9999999999, "role": "user"})
        results = attacker.attack_expired_token(token, secret="secret")
        assert len(results) == 1
        assert results[0].attack_id == "JWT-04"

    def test_no_false_positive_when_exp_validated(self):
        """만료된 토큰에 401 → False Positive 없음"""
        tracker = _CallTracker()
        tracker._default = _MockResponse(401, "Token expired")

        attacker = JWTAttacker(tracker, [TARGET_URL])
        token = _make_token(payload={"sub": "1234", "exp": 9999999999})
        results = attacker.attack_expired_token(token, secret="secret")
        assert results == []

    def test_skip_when_no_exp_claim(self):
        """exp 클레임이 없으면 스킵"""
        tracker = _CallTracker()
        attacker = JWTAttacker(tracker, [TARGET_URL])
        token = _make_token(payload={"sub": "1234"})  # exp 없음
        results = attacker.attack_expired_token(token, secret="secret")
        assert results == []

    def test_with_none_alg(self):
        """use_none_alg=True 모드로도 동작"""
        tracker = _CallTracker()
        tracker._default = _MockResponse(200, '{"user":"test"}')

        attacker = JWTAttacker(tracker, [TARGET_URL])
        token = _make_token(payload={"sub": "1234", "exp": 9999999999})
        results = attacker.attack_expired_token(token, secret=None, use_none_alg=True)
        assert len(results) == 1


# ── JWT-05 Privilege Escalation ───────────────────────────────────────────────

class TestAttackPrivilegeEscalation:
    def test_detects_privilege_escalation(self):
        """role 조작 토큰에 200 응답 → 권한 상승 탐지"""
        tracker = _CallTracker()
        tracker._default = _MockResponse(200, '{"user":"admin"}')

        attacker = JWTAttacker(tracker, [TARGET_URL])
        token = _make_token(payload={"sub": "1234", "role": "user"})
        results = attacker.attack_privilege_escalation(token, secret="secret")
        assert len(results) == 1
        assert results[0].attack_id == "JWT-05"

    def test_no_privilege_claims_no_attack(self):
        """권한 관련 클레임이 없으면 공격 스킵"""
        tracker = _CallTracker()
        attacker = JWTAttacker(tracker, [TARGET_URL])
        token = _make_token(payload={"sub": "1234", "name": "Alice"})
        results = attacker.attack_privilege_escalation(token, secret="secret")
        assert results == []

    def test_no_false_positive_when_role_validated(self):
        """조작된 토큰에 403 → False Positive 없음"""
        tracker = _CallTracker()
        tracker._default = _MockResponse(403, "Forbidden")

        attacker = JWTAttacker(tracker, [TARGET_URL])
        token = _make_token(payload={"sub": "1234", "role": "user"})
        results = attacker.attack_privilege_escalation(token, secret="secret")
        assert results == []


# ── JWT-07 kid Injection ──────────────────────────────────────────────────────

class TestAttackKidInjection:
    def test_skip_when_no_kid_header(self):
        """kid 클레임이 없으면 스킵"""
        tracker = _CallTracker()
        attacker = JWTAttacker(tracker, [TARGET_URL])
        token = _make_token()
        results = attacker.attack_kid_injection(token)
        assert results == []

    def test_detects_sql_error_in_response(self):
        """SQL 에러 메시지 응답 → SQL Injection 탐지"""
        tracker = _CallTracker()
        tracker._default = _MockResponse(500, "You have an error in your SQL syntax")

        attacker = JWTAttacker(tracker, [TARGET_URL])
        # kid 클레임이 있는 토큰 직접 구성
        h = _json_b64({"alg": "HS256", "typ": "JWT", "kid": "1"})
        p = _json_b64({"sub": "1234"})
        token = ANALYZER.parse(f"{h}.{p}.fakesig", source="test")
        results = attacker.attack_kid_injection(token)
        assert len(results) >= 1
        assert results[0].attack_id == "JWT-07"

    def test_detects_auth_bypass_via_sql(self):
        """UNION SELECT 주입 후 인증 성공 → SQL Injection 탐지"""
        tracker = _CallTracker()
        # 모든 kid 인젝션 요청에 200 반환
        tracker._default = _MockResponse(200, '{"user":"admin"}')

        attacker = JWTAttacker(tracker, [TARGET_URL])
        h = _json_b64({"alg": "HS256", "typ": "JWT", "kid": "1"})
        p = _json_b64({"sub": "1234"})
        token = ANALYZER.parse(f"{h}.{p}.fakesig", source="test")
        results = attacker.attack_kid_injection(token)
        assert len(results) >= 1
        assert results[0].attack_id == "JWT-07"
