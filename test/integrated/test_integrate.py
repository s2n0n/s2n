"""HTTP Response Headers 보안 통합 테스트

이 파일은 HTTP 응답 헤더 보안 검사 기능을 통합적으로 테스트합니다.
주로 CSRF 보호 헤더(X-Frame-Options, Content-Security-Policy, SameSite 등)를
검증하는 scan_res_headers 함수와 전체 CSRF 스캔 플로우를 테스트합니다.

통합 테스트 원칙:
1. MockHTTPClient, MockRequest, MockResponse 사용 (외부 패키지 사용 금지)
2. 실제 HTTP 요청 없이 전체 플로우 검증
3. 다양한 헤더 조합 시나리오 테스트
"""

import pytest
from test.mock_data import MockHTTPClient, MockRequest, MockResponse, MockPluginContext
from s2n.s2nscanner.plugins.csrf.csrf_scan import scan_res_headers, csrf_scan
from s2n.s2nscanner.interfaces import Severity


@pytest.mark.integration
def test_scan_res_headers_all_missing():
    """모든 보안 헤더가 없는 경우 - MEDIUM severity"""
    headers = {}

    results = scan_res_headers(headers)

    assert isinstance(results, list)
    assert len(results) >= 2
    for result in results:
        assert result.plugin == "csrf"
        assert result.severity == Severity.MEDIUM
        assert result.cwe_id == "CWE-352"
    
    titles = [r.title for r in results]
    assert any("Missing X-Frame-Options" in t for t in titles)
    assert any("Missing Content-Security-Policy" in t for t in titles)


@pytest.mark.integration
def test_scan_res_headers_all_present():
    """모든 보안 헤더가 존재하는 경우 - INFO severity"""
    headers = {
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
        "SameSite": "Strict",
    }

    results = scan_res_headers(headers)

    assert isinstance(results, list)
    assert len(results) == 1
    
    result = results[0]
    assert result.plugin == "csrf"
    assert result.severity == Severity.INFO
    assert "Adequate" in result.title
    assert result.cvss_score is None


@pytest.mark.integration
def test_scan_res_headers_partial():
    """일부 보안 헤더만 존재하는 경우"""
    headers = {
        "X-Frame-Options": "SAMEORIGIN"
        # Content-Security-Policy 누락
    }

    results = scan_res_headers(headers)

    assert isinstance(results, list)
    assert any(r.severity == Severity.MEDIUM for r in results)
    
    titles = [r.title for r in results]
    assert any("Missing Content-Security-Policy" in t for t in titles)
    assert not any("Missing X-Frame-Options" in t for t in titles)


@pytest.mark.integration
def test_scan_res_headers_case_sensitivity():
    """헤더 이름의 대소문자 구분 테스트"""
    # HTTP 헤더는 대소문자를 구분하지 않지만, 딕셔너리 키는 구분함
    headers = {
        "x-frame-options": "DENY",  # 소문자
        "content-security-policy": "default-src 'self'",  # 소문자
    }

    results = scan_res_headers(headers)

    # 현재 구현은 대소문자를 구분하므로 누락으로 판단됨
    assert any(r.severity == Severity.MEDIUM for r in results)
    titles = [r.title for r in results]
    assert any("Missing X-Frame-Options" in t for t in titles)
    assert any("Missing Content-Security-Policy" in t for t in titles)


@pytest.mark.integration
def test_scan_res_headers_extra_headers():
    """필수 헤더 외에 추가 보안 헤더가 있는 경우"""
    headers = {
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
        "SameSite": "Strict",
        "X-Content-Type-Options": "nosniff",  # 추가 헤더
        "Strict-Transport-Security": "max-age=31536000",  # 추가 헤더
        "X-XSS-Protection": "1; mode=block",  # 추가 헤더
    }

    results = scan_res_headers(headers)

    # 필수 헤더가 모두 있으므로 INFO
    assert len(results) == 1
    assert results[0].severity == Severity.INFO
    assert "Adequate" in results[0].title


@pytest.mark.integration
def test_csrf_scan_integration_with_missing_headers():
    """csrf_scan 전체 플로우 - 보안 헤더 누락 시나리오"""

    # MockResponse를 반환하는 MockSession 설정
    class CustomMockSession:
        def __init__(self):
            self.headers = {"User-Agent": "test"}

        def get(self, url, timeout=10):
            # 보안 헤더가 없는 응답
            response = MockResponse(
                text="<html><body><form><input name='csrf_token' /></form></body></html>"
            )
            response.headers = {}  # 보안 헤더 없음
            return response

    # MockHTTPClient에 커스텀 세션 설정
    http_client = MockHTTPClient()
    http_client.s = CustomMockSession()

    target_url = "http://example.com/test"
    results = csrf_scan(target_url, http_client=http_client, plugin_context=None)

    assert isinstance(results, list)
    assert len(results) >= 2

    # http_result (scan_res_headers의 결과) 검증 - Missing XFO 및 Missing CSP
    header_findings = [r for r in results if r.severity == Severity.MEDIUM and "Missing" in r.title]
    assert len(header_findings) >= 2


@pytest.mark.integration
def test_csrf_scan_integration_with_all_headers():
    """csrf_scan 전체 플로우 - 모든 보안 헤더 존재 시나리오"""

    class CustomMockSession:
        def __init__(self):
            self.headers = {"User-Agent": "test"}

        def get(self, url, timeout=10):
            # 모든 보안 헤더가 있는 응답
            response = MockResponse(
                text="<html><body><form><input name='csrf_token' /></form></body></html>"
            )
            response.headers = {
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'self'",
                "SameSite": "Strict",
            }
            return response

    http_client = MockHTTPClient()
    http_client.s = CustomMockSession()

    target_url = "http://example.com/secure"
    results = csrf_scan(target_url, http_client=http_client, plugin_context=None)

    assert isinstance(results, list)
    assert len(results) >= 1

    # http_result 검증
    header_finding = next((r for r in results if "Adequate" in r.title), None)
    assert header_finding is not None
    assert header_finding.severity == Severity.INFO


@pytest.mark.integration
def test_csrf_scan_with_plugin_context():
    """PluginContext를 사용한 csrf_scan 통합 테스트"""
    # MockPluginContext 생성
    target_url = "http://example.com/api"
    context = MockPluginContext(obj={"target_urls": [target_url]})

    class CustomMockSession:
        def __init__(self):
            self.headers = {"User-Agent": "s2n_csrf/1.0"}

        def get(self, url, timeout=10):
            response = MockResponse(
                text="<html><body><p>API Endpoint</p></body></html>"
            )
            response.headers = {
                "Content-Security-Policy": "default-src 'self'"
                # X-Frame-Options 누락
            }
            return response

    http_client = MockHTTPClient()
    http_client.s = CustomMockSession()

    results = csrf_scan(target_url, http_client=http_client, plugin_context=context)

    assert isinstance(results, list)
    assert len(results) >= 1

    # 부분적으로 헤더가 누락된 경우
    missing_xfo = next((r for r in results if "Missing X-Frame-Options" in r.title), None)
    assert missing_xfo is not None
    assert missing_xfo.severity == Severity.MEDIUM


@pytest.mark.integration
def test_multiple_urls_header_scanning():
    """여러 URL에 대한 헤더 스캔 시뮬레이션"""
    test_cases = [
        {
            "url": "http://example.com/page1",
            "headers": {},
            "expected_severity": Severity.MEDIUM,
        },
        {
            "url": "http://example.com/page2",
            "headers": {
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'self'",
                "SameSite": "Lax",
            },
            "expected_severity": Severity.INFO,
        },
        {
            "url": "http://example.com/page3",
            "headers": {"X-Frame-Options": "SAMEORIGIN"},
            "expected_severity": Severity.MEDIUM,
        },
    ]

    results = []
    for test_case in test_cases:
        res_list = scan_res_headers(test_case["headers"])
        results.append({"url": test_case["url"], "result": res_list})

    # 각 결과 검증
    # 첫 번째 URL (모두 누락) -> MEDIUM
    assert any(r.severity == Severity.MEDIUM for r in results[0]["result"])
    # 두 번째 URL (모두 존재) -> INFO (Lax makes SameSite pass? Wait, test says Lax. csrf_scan says secure values include Lax? Let's check.)
    # In earlier test, SameSite=Lax might be considered secure enough or INFO.
    # Actually, previous test asserted Severity.INFO for the second test_case.
    # We will just assert that at least one finding has the expected severity, or the maximum severity is expected.
    assert max(r.severity for r in results[0]["result"]) == Severity.MEDIUM
    
    # second URL: should only have INFO
    assert max(r.severity for r in results[1]["result"]) == Severity.INFO
    
    # third URL: missing CSP -> MEDIUM
    assert max(r.severity for r in results[2]["result"]) == Severity.MEDIUM

    # 총 3개의 URL 스캔 완료
    assert len(results) == 3


@pytest.mark.integration
def test_header_values_with_different_policies():
    """다양한 헤더 정책 값 테스트"""
    test_scenarios = [
        {
            "name": "DENY policy",
            "headers": {
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'none'",
            },
            "expected": Severity.INFO,
        },
        {
            "name": "SAMEORIGIN policy with unsafe-inline",
            "headers": {
                "X-Frame-Options": "SAMEORIGIN",
                "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
            },
            "expected": Severity.LOW,  # CSP contains unsafe directive
        },
        {
            "name": "Empty CSP value",
            "headers": {
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "",  # 빈 값
            },
            "expected": Severity.MEDIUM,  # 빈 값은 보호를 제공하지 않으므로 누락된 것으로 간주됨
        },
    ]

    for scenario in test_scenarios:
        res_list = scan_res_headers(scenario["headers"])
        max_severity = max(r.severity for r in res_list) if res_list else Severity.INFO
        assert max_severity == scenario["expected"], f"Failed for {scenario['name']}"


@pytest.mark.integration
def test_csrf_scan_error_handling():
    """csrf_scan의 예외 처리 테스트"""

    # 잘못된 세션을 가진 http_client
    class BrokenMockSession:
        def __init__(self):
            self.headers = {}

        def get(self, url, timeout=10):
            raise Exception("Network error simulated")

    http_client = MockHTTPClient()
    http_client.s = BrokenMockSession()

    target_url = "http://example.com/broken"
    results = csrf_scan(target_url, http_client=http_client, plugin_context=None)

    # 예외 발생 시 빈 리스트 반환
    assert isinstance(results, list)
    assert len(results) == 0


@pytest.mark.integration
def test_headers_with_unicode_and_special_chars():
    """유니코드 및 특수 문자가 포함된 헤더 테스트"""
    headers = {
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'; script-src https://cdn.example.com",
        "SameSite": "Strict; 한글=테스트",  # 특수 케이스
    }

    results = scan_res_headers(headers)

    # 모든 필수 헤더가 존재하므로 INFO
    assert len(results) == 1
    assert results[0].severity == Severity.INFO


@pytest.mark.integration
def test_scan_res_headers_remediation_and_references():
    """결과 객체의 remediation과 references 필드 검증"""
    # 헤더 누락 케이스
    results_missing = scan_res_headers({})

    assert len(results_missing) > 0
    assert results_missing[0].remediation is not None
    assert "appropriate security headers" in results_missing[0].remediation
    assert len(results_missing[0].references) > 0
    assert any("owasp.org" in ref for ref in results_missing[0].references)

    # 헤더 존재 케이스
    results_present = scan_res_headers(
        {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "SameSite": "Strict",
        }
    )

    assert len(results_present) == 1
    assert results_present[0].remediation is not None
    assert len(results_present[0].references) > 0
