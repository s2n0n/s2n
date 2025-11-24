
import pytest
from unittest.mock import MagicMock, patch
from types import SimpleNamespace
from s2n.s2nscanner.plugins.soft_brute_force.soft_brute_force_main import SoftBruteForcePlugin
from s2n.s2nscanner.interfaces import PluginStatus, Severity

class MockResponse:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code

@pytest.fixture
def mock_context():
    client = MagicMock()
    scan_context = SimpleNamespace(
        config=SimpleNamespace(target_url="http://example.com/login"),
        http_client=client,
        target_url="http://example.com/login"
    )
    return SimpleNamespace(scan_context=scan_context, plugin_name="soft_brute_force")

def test_rate_limiting_detected_429(mock_context):
    """
    429(Too Many Requests) 응답이 오면 Rate Limiting이 작동하는 것으로 판단하여
    취약점(Finding)을 보고하지 않아야 함 (안전함).
    """
    plugin = SoftBruteForcePlugin()
    
    # Mock 응답: 첫 요청은 정상, 이후 요청은 429 에러
    mock_context.scan_context.http_client.get.return_value = MockResponse("Login Page")
    mock_context.scan_context.http_client.post.return_value = MockResponse("Too Many Requests", 429)
    
    result = plugin.run(mock_context)
    
    # 성공적으로 실행되었으나(SUCCESS), 취약점은 없어야 함(len=0)
    assert result.status == PluginStatus.SUCCESS
    assert len(result.findings) == 0 # Safe

def test_rate_limiting_not_detected(mock_context):
    """
    반복적인 실패 요청에도 차단 없이 200 OK가 계속되면
    Rate Limiting이 없는 것으로 판단하여 취약점을 보고해야 함.
    """
    plugin = SoftBruteForcePlugin()
    
    # Mock 응답: 모든 요청에 대해 200 OK, 차단 키워드 없음
    mock_context.scan_context.http_client.get.return_value = MockResponse("Login Page")
    mock_context.scan_context.http_client.post.return_value = MockResponse("Login Failed", 200)
    
    result = plugin.run(mock_context)
    
    assert result.status == PluginStatus.SUCCESS
    assert len(result.findings) >= 1
    assert result.findings[0].title == "No Rate Limiting Detected"

def test_default_credentials_found(mock_context):
    """
    기본 계정(admin/admin)으로 로그인 성공 시 취약점을 보고해야 함.
    """
    plugin = SoftBruteForcePlugin()
    
    mock_context.scan_context.http_client.get.return_value = MockResponse("Login Page")
    
    def side_effect(url, data=None, **kwargs):
        if data and data.get("username") == "admin" and data.get("password") == "admin":
            return MockResponse("Welcome Admin", 200)
        return MockResponse("Login Failed", 200)
        
    mock_context.scan_context.http_client.post.side_effect = side_effect
    
    result = plugin.run(mock_context)
    
    # 예상 결과:
    # 1. Rate Limiting 취약점 (쓰레기 값 요청에 대해 차단 안 함)
    # 2. Default Credential 취약점 (admin/admin 성공)
    
    titles = [f.title for f in result.findings]
    assert "Default Credentials Found" in titles
    assert "No Rate Limiting Detected" in titles
