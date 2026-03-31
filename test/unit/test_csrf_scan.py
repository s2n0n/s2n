from test.mock_data import MockHTTPClient, MockRequest
from test.unit.test_csrf_data import (
    HTML_NO_FORMS,
    HTML_WITH_CSRF_TOKEN,
    HTML_WITHOUT_CSRF,
    HTML_WITH_STATIC_TOKEN,
    HTML_GET_FORM_NO_TOKEN,
    HTML_WITH_META_TOKEN,
    HTML_WITH_META_TOKEN_STATIC,
    HTML_WITH_META_TOKEN_EMPTY,
    HTML_WITH_JS_TOKEN,
    HTML_WITH_JS_TOKEN_STATIC,
)

from s2n.s2nscanner.plugins.csrf import csrf_scan as csrf_scan_module


# ---------------------------------------------------------------------------
# L3: scan_res_headers
# ---------------------------------------------------------------------------

def test_scan_res_headers_missing_all():
    findings = csrf_scan_module.scan_res_headers({})
    assert isinstance(findings, list)
    assert len(findings) >= 2
    titles = [f.title for f in findings]
    assert any("X-Frame-Options" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)


def test_scan_res_headers_all_good():
    findings = csrf_scan_module.scan_res_headers(
        {"X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'self'"}
    )
    assert len(findings) == 1
    assert findings[0].severity.name == "INFO"


def test_scan_res_headers_weak_xfo():
    findings = csrf_scan_module.scan_res_headers(
        {"X-Frame-Options": "ALLOW-FROM http://evil.com", "Content-Security-Policy": "default-src 'self'"}
    )
    xfo_findings = [f for f in findings if "X-Frame-Options" in f.title]
    assert len(xfo_findings) == 1
    assert xfo_findings[0].severity.name == "LOW"


def test_scan_res_headers_samesite_none():
    findings = csrf_scan_module.scan_res_headers(
        {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Set-Cookie": "session=abc; SameSite=None; Secure",
        }
    )
    samesite_findings = [f for f in findings if "SameSite" in f.title]
    assert len(samesite_findings) == 1
    assert samesite_findings[0].severity.name == "HIGH"


def test_scan_res_headers_samesite_missing():
    findings = csrf_scan_module.scan_res_headers(
        {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Set-Cookie": "session=abc; HttpOnly; Secure",
        }
    )
    samesite_findings = [f for f in findings if "SameSite" in f.title]
    assert len(samesite_findings) == 1
    assert samesite_findings[0].severity.name == "MEDIUM"


# ---------------------------------------------------------------------------
# L1 + L2: scan_form_tags
# ---------------------------------------------------------------------------

def test_scan_form_tags_no_forms():
    resp = MockRequest()
    findings = csrf_scan_module.scan_form_tags(HTML_NO_FORMS, HTML_NO_FORMS, resp, "http://t")
    assert len(findings) == 1
    assert "No Form Tags Found" in findings[0].title


def test_scan_form_tags_post_missing_token():
    resp = MockRequest()
    findings = csrf_scan_module.scan_form_tags(HTML_WITHOUT_CSRF, HTML_WITHOUT_CSRF, resp, "http://t")
    high_findings = [f for f in findings if f.severity.name == "HIGH"]
    assert len(high_findings) >= 1
    assert "Missing CSRF Token" in high_findings[0].title


def test_scan_form_tags_with_token():
    html2 = HTML_WITH_CSRF_TOKEN.replace("abc123", "def456")
    resp = MockRequest()
    findings = csrf_scan_module.scan_form_tags(HTML_WITH_CSRF_TOKEN, html2, resp, "http://t")
    assert all(f.severity.name == "INFO" for f in findings)


def test_scan_form_tags_static_token():
    resp = MockRequest()
    findings = csrf_scan_module.scan_form_tags(
        HTML_WITH_STATIC_TOKEN, HTML_WITH_STATIC_TOKEN, resp, "http://t"
    )
    static_findings = [f for f in findings if "Static" in f.title]
    assert len(static_findings) == 1
    assert static_findings[0].severity.name == "MEDIUM"


def test_scan_form_tags_get_form_no_token():
    resp = MockRequest()
    findings = csrf_scan_module.scan_form_tags(
        HTML_GET_FORM_NO_TOKEN, HTML_GET_FORM_NO_TOKEN, resp, "http://t"
    )
    low_findings = [f for f in findings if f.severity.name == "LOW"]
    assert len(low_findings) >= 1
    assert "GET" in low_findings[0].title


# ---------------------------------------------------------------------------
# L4: scan_origin_validation
# ---------------------------------------------------------------------------

def test_scan_origin_validation_no_validation():
    class FakeResp:
        status_code = 200
        text = "<html>same content</html>"
        headers = {}
    class FakeSession:
        headers = {}
        def get(self, url, timeout=10, headers=None):
            return FakeResp()

    findings = csrf_scan_module.scan_origin_validation(FakeSession(), "http://t")
    assert len(findings) >= 1
    assert any("Origin" in f.title for f in findings)


def test_scan_origin_validation_server_rejects():
    class NormalResp:
        status_code = 200
        text = "ok"
        headers = {}
    class ForbiddenResp:
        status_code = 403
        text = "Forbidden"
        headers = {}
    class FakeSession:
        headers = {}
        call_count = 0
        def get(self, url, timeout=10, headers=None):
            self.call_count += 1
            if headers and "Origin" in headers:
                return ForbiddenResp()
            return NormalResp()

    findings = csrf_scan_module.scan_origin_validation(FakeSession(), "http://t")
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# L5: scan_meta_tokens
# ---------------------------------------------------------------------------

def test_scan_meta_tokens_unique():
    """Different meta token values across two responses -> no finding."""
    html2 = HTML_WITH_META_TOKEN.replace("meta_token_abc123", "meta_token_def456")
    findings = csrf_scan_module.scan_meta_tokens(HTML_WITH_META_TOKEN, html2, "http://t")
    assert len(findings) == 0


def test_scan_meta_tokens_static():
    """Same meta token value -> MEDIUM static warning."""
    findings = csrf_scan_module.scan_meta_tokens(
        HTML_WITH_META_TOKEN_STATIC, HTML_WITH_META_TOKEN_STATIC, "http://t"
    )
    assert len(findings) == 1
    assert "Static" in findings[0].title
    assert findings[0].severity.name == "MEDIUM"


def test_scan_meta_tokens_empty():
    """Empty meta token content -> MEDIUM warning."""
    findings = csrf_scan_module.scan_meta_tokens(
        HTML_WITH_META_TOKEN_EMPTY, HTML_WITH_META_TOKEN_EMPTY, "http://t"
    )
    assert len(findings) == 1
    assert "Empty" in findings[0].title


def test_scan_meta_tokens_no_meta():
    """HTML without meta tokens -> no finding (not necessarily bad)."""
    findings = csrf_scan_module.scan_meta_tokens(HTML_NO_FORMS, HTML_NO_FORMS, "http://t")
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# L6: scan_js_tokens
# ---------------------------------------------------------------------------

def test_scan_js_tokens_unique():
    """Different JS token values -> no finding."""
    html2 = HTML_WITH_JS_TOKEN.replace("js_dynamic_token_abc", "js_dynamic_token_xyz")
    findings = csrf_scan_module.scan_js_tokens(HTML_WITH_JS_TOKEN, html2, "http://t")
    assert len(findings) == 0


def test_scan_js_tokens_static():
    """Same JS token value -> MEDIUM static warning."""
    findings = csrf_scan_module.scan_js_tokens(
        HTML_WITH_JS_TOKEN_STATIC, HTML_WITH_JS_TOKEN_STATIC, "http://t"
    )
    assert len(findings) == 1
    assert "Static" in findings[0].title
    assert findings[0].severity.name == "MEDIUM"


def test_scan_js_tokens_no_tokens():
    """HTML without JS tokens -> no finding."""
    findings = csrf_scan_module.scan_js_tokens(HTML_NO_FORMS, HTML_NO_FORMS, "http://t")
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# L7: scan_custom_header_requirement
# ---------------------------------------------------------------------------

def test_scan_custom_header_no_validation():
    """Session that always returns same response -> finding."""
    class FakeResp:
        status_code = 200
        text = "<html>same</html>"
    class FakeSession:
        headers = {}
        def get(self, url, timeout=10, headers=None):
            return FakeResp()

    findings = csrf_scan_module.scan_custom_header_requirement(FakeSession(), "http://t")
    assert len(findings) == 1
    assert "X-Requested-With" in findings[0].title
    assert findings[0].severity.name == "LOW"


def test_scan_custom_header_validated():
    """Session that returns 403 without custom header -> no finding."""
    class OkResp:
        status_code = 200
        text = "ok"
    class ForbiddenResp:
        status_code = 403
        text = "Forbidden"
    class FakeSession:
        headers = {}
        def get(self, url, timeout=10, headers=None):
            if headers and "X-Requested-With" in headers:
                return OkResp()
            return ForbiddenResp()

    findings = csrf_scan_module.scan_custom_header_requirement(FakeSession(), "http://t")
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# L8: CORS misconfiguration (via _check_cors_headers)
# ---------------------------------------------------------------------------

def test_cors_wildcard_with_credentials():
    findings = csrf_scan_module._check_cors_headers(
        {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
        "https://evil.example.com",
        "http://t",
    )
    assert len(findings) == 1
    assert "Wildcard" in findings[0].title
    assert findings[0].severity.name == "HIGH"


def test_cors_origin_reflection_with_credentials():
    findings = csrf_scan_module._check_cors_headers(
        {
            "Access-Control-Allow-Origin": "https://evil.example.com",
            "Access-Control-Allow-Credentials": "true",
        },
        "https://evil.example.com",
        "http://t",
    )
    assert len(findings) == 1
    assert "Reflection" in findings[0].title
    assert "Credentials" in findings[0].title
    assert findings[0].severity.name == "HIGH"


def test_cors_origin_reflection_no_credentials():
    findings = csrf_scan_module._check_cors_headers(
        {"Access-Control-Allow-Origin": "https://evil.example.com"},
        "https://evil.example.com",
        "http://t",
    )
    assert len(findings) == 1
    assert findings[0].severity.name == "MEDIUM"


def test_cors_wildcard_no_credentials():
    findings = csrf_scan_module._check_cors_headers(
        {"Access-Control-Allow-Origin": "*"},
        "https://evil.example.com",
        "http://t",
    )
    assert len(findings) == 1
    assert findings[0].severity.name == "LOW"


def test_cors_no_acao():
    findings = csrf_scan_module._check_cors_headers(
        {},
        "https://evil.example.com",
        "http://t",
    )
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------

def test_csrf_scan_integration_with_mock_session():
    http_client = MockHTTPClient()
    results = csrf_scan_module.csrf_scan(
        "http://example.local", http_client=http_client, plugin_context=None
    )  # type: ignore
    assert isinstance(results, list)
    assert len(results) >= 1
