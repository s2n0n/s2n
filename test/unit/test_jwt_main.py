"""JWTPlugin 통합 단위 테스트"""
import hashlib
import hmac

import pytest
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

from s2n.s2nscanner.plugins.jwt.jwt_main import JWTPlugin, main
from s2n.s2nscanner.plugins.jwt.jwt_analyzer import _json_b64, _b64url_encode
from s2n.s2nscanner.interfaces import PluginStatus, Severity


# ── Mock 인프라 ──────────────────────────────────────────────────────────────

class _MockResponse:
    def __init__(self, status_code: int = 200, text: str = '{"ok":true}'):
        self.status_code = status_code
        self.text = text


class _MockHTTPClient:
    def __init__(self, default_status=401, default_text="Unauthorized"):
        self._default = _MockResponse(default_status, default_text)
        self.s = SimpleNamespace(headers={}, cookies=[])
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url))
        return self._default

    def request(self, method, url, **kwargs):
        self.calls.append((method, url))
        return self._default


def _make_hs256_token(payload: dict, secret: str = "secret") -> str:
    h_b64 = _json_b64({"alg": "HS256", "typ": "JWT"})
    p_b64 = _json_b64(payload)
    msg = f"{h_b64}.{p_b64}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"


def _make_plugin_context(token: str = None, target_url: str = "http://target.local/api"):
    """테스트용 PluginContext를 생성합니다."""
    auth_config = SimpleNamespace(
        token=token,
        headers={},
        cookies={},
    )
    config = SimpleNamespace(
        target_url=target_url,
        auth_config=auth_config,
    )
    client = _MockHTTPClient()
    scan_context = SimpleNamespace(
        target_url=target_url,
        config=config,
        http_client=client,
    )
    return SimpleNamespace(
        plugin_name="jwt",
        scan_context=scan_context,
        plugin_config=SimpleNamespace(custom_params={}),
        target_urls=[target_url],
        logger=None,
    )


# ── main() 팩토리 ─────────────────────────────────────────────────────────────

class TestMain:
    def test_main_returns_jwt_plugin(self):
        plugin = main()
        assert isinstance(plugin, JWTPlugin)
        assert plugin.name == "jwt"

    def test_main_with_config(self):
        plugin = main({"timeout": 10})
        assert plugin.timeout == 10


# ── SKIPPED 케이스 ────────────────────────────────────────────────────────────

class TestJWTPluginSkipped:
    def test_returns_skipped_when_no_jwt(self):
        """JWT 토큰이 없으면 SKIPPED 반환"""
        plugin = JWTPlugin()
        ctx = _make_plugin_context(token=None)
        result = plugin.run(ctx)
        assert result.status == PluginStatus.SKIPPED
        assert result.findings == []

    def test_skipped_has_no_error(self):
        plugin = JWTPlugin()
        ctx = _make_plugin_context(token=None)
        result = plugin.run(ctx)
        assert result.error is None


# ── SUCCESS 케이스 (취약점 없음) ──────────────────────────────────────────────

class TestJWTPluginSuccess:
    def test_returns_success_when_no_findings(self):
        """JWT 있지만 공격 실패 → SUCCESS (PARTIAL 아님)"""
        token = _make_hs256_token({"sub": "1234", "role": "user"}, "super_strong_key_32b!!")
        plugin = JWTPlugin()
        ctx = _make_plugin_context(token=token)
        # 모든 HTTP 요청에 401 반환 → 공격 실패
        ctx.scan_context.http_client._default = _MockResponse(401, "Unauthorized")
        result = plugin.run(ctx)
        assert result.status == PluginStatus.SUCCESS
        assert result.findings == []


# ── PARTIAL 케이스 (취약점 발견) ──────────────────────────────────────────────

class TestJWTPluginPartial:
    def test_jwt06_sensitive_data_creates_finding(self):
        """페이로드에 password 클레임 → JWT-06 Finding 생성"""
        token = _make_hs256_token(
            {"sub": "1234", "password": "mysecret123"}, "strong_secret_key_32!!"
        )
        plugin = JWTPlugin()
        ctx = _make_plugin_context(token=token)
        ctx.scan_context.http_client._default = _MockResponse(401, "Unauthorized")
        result = plugin.run(ctx)
        assert result.status == PluginStatus.PARTIAL
        jwt06_findings = [f for f in result.findings if "Sensitive" in f.title]
        assert len(jwt06_findings) >= 1
        assert jwt06_findings[0].cwe_id == "CWE-312"

    def test_jwt01_finding_when_none_alg_succeeds(self):
        """none alg 공격 성공 → JWT-01 Finding 생성"""
        token_str = _make_hs256_token({"sub": "1234", "role": "user"}, "secret")
        plugin = JWTPlugin()
        ctx = _make_plugin_context(token=token_str)

        call_count = [0]

        def smart_get(url, **kwargs):
            headers = kwargs.get("headers", {})
            auth = headers.get("Authorization", "")
            call_count[0] += 1
            # 인증 없으면 401, none alg 토큰이면 200
            if not auth or auth in ("", "Bearer "):
                return _MockResponse(401, "Unauthorized")
            # none alg 토큰 (서명 없이 .으로 끝나는 경우)
            token_part = auth.replace("Bearer ", "")
            if token_part.endswith("."):
                return _MockResponse(200, '{"user":"admin"}')
            return _MockResponse(401, "Unauthorized")

        ctx.scan_context.http_client.get = smart_get
        result = plugin.run(ctx)
        jwt01_findings = [f for f in result.findings if "None" in f.title or "none" in f.title.lower()]
        assert len(jwt01_findings) >= 1
        assert jwt01_findings[0].severity == Severity.CRITICAL

    def test_jwt02_finding_when_secret_cracked(self):
        """약한 시크릿 크래킹 성공 → JWT-02 Finding 생성"""
        token_str = _make_hs256_token({"sub": "1234"}, "secret")  # 약한 시크릿
        plugin = JWTPlugin()
        ctx = _make_plugin_context(token=token_str)
        ctx.scan_context.http_client._default = _MockResponse(401, "Unauthorized")
        result = plugin.run(ctx)
        jwt02_findings = [f for f in result.findings if "Weak" in f.title]
        assert len(jwt02_findings) >= 1
        assert jwt02_findings[0].cwe_id == "CWE-326"


# ── FAILED 케이스 ─────────────────────────────────────────────────────────────

class TestJWTPluginFailed:
    def test_returns_failed_on_exception(self):
        """내부 예외 발생 시 FAILED 반환"""
        plugin = JWTPlugin()
        ctx = _make_plugin_context(token="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig")

        # resolve_target_url이 예외를 던지도록
        with patch(
            "s2n.s2nscanner.plugins.jwt.jwt_main.resolve_target_url",
            side_effect=RuntimeError("Test error"),
        ):
            result = plugin.run(ctx)

        assert result.status == PluginStatus.FAILED
        assert result.error is not None
        assert result.error.error_type == "RuntimeError"


# ── Finding 품질 검증 ─────────────────────────────────────────────────────────

class TestFindingQuality:
    def test_all_findings_have_required_fields(self):
        """모든 Finding이 필수 필드를 가지는지 검증"""
        token = _make_hs256_token({"sub": "1", "password": "pw"}, "secret")
        plugin = JWTPlugin()
        ctx = _make_plugin_context(token=token)
        ctx.scan_context.http_client._default = _MockResponse(401, "Unauthorized")
        result = plugin.run(ctx)

        for finding in result.findings:
            assert finding.id is not None and finding.id != ""
            assert finding.plugin == "jwt"
            assert finding.title is not None and finding.title != ""
            assert finding.description is not None
            assert finding.cwe_id is not None
            assert finding.remediation is not None
            assert len(finding.references) > 0
            assert finding.cvss_score is not None

    def test_finding_ids_are_unique(self):
        token = _make_hs256_token({"sub": "1", "password": "pw", "role": "user"}, "secret")
        plugin = JWTPlugin()
        ctx = _make_plugin_context(token=token)
        ctx.scan_context.http_client._default = _MockResponse(401, "Unauthorized")
        result = plugin.run(ctx)

        ids = [f.id for f in result.findings]
        assert len(ids) == len(set(ids)), "Finding ID 중복 발생"
