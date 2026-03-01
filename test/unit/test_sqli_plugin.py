
from s2n.s2nscanner.logger import get_logger
import pytest
from unittest.mock import MagicMock, patch
from s2n.s2nscanner.plugins.sqlinjection.sqli_main import SQLInjectionPlugin
from s2n.s2nscanner.interfaces import PluginStatus
from types import SimpleNamespace

class MockResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code

class MockHttpClient:
    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        if "id=1' OR '1'='1' -- " in url:
            return MockResponse("ID: 1, admin") # Success indicator
        return MockResponse("safe response")

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return MockResponse("safe response")

@pytest.fixture
def mock_context():
    client = MockHttpClient()
    scan_context = SimpleNamespace(
        target_url="http://example.com/page.php?id=1",
        http_client=client,
        auth_config=SimpleNamespace(auth_adapter=None)
    )
    logger = get_logger()
    return SimpleNamespace(scan_context=scan_context, logger=logger)

def test_sqli_plugin_detects_boolean_based(mock_context):
    plugin = SQLInjectionPlugin()
    result = plugin.run(mock_context)
    print("PluginStatus: %s", result)
    
    # TODO: Partial reason
    assert result.status == PluginStatus.PARTIAL
    assert len(result.findings) > 0
    finding = result.findings[0]
    assert "SQL Injection" in finding.title
    assert "' OR '1'='1' -- " in finding.payload

def test_sqli_plugin_sends_sleep_payload(mock_context):
    # This test verifies that the sleep payload is sent
    plugin = SQLInjectionPlugin()

    with patch('s2n.s2nscanner.plugins.sqlinjection.sqli_scan.crawl_recursive') as mock_crawl, \
         patch('s2n.s2nscanner.plugins.sqlinjection.sqli_scan.time.time') as mock_time:
        # Return only the target URL from crawl (avoid extra HTTP calls)
        mock_crawl.return_value = ["http://example.com/page.php"]

        # time.time() is called twice per time-based payload (start, end)
        # elapsed = 6 - 0 = 6 > TIME_THRESHOLD(0.9), so first payload is detected
        mock_time.side_effect = [0, 6]

        # All GET responses return "safe" (no SQL success/error indicators)
        # This ensures all boolean/error checks fail, reaching time-based checks
        mock_context.scan_context.http_client.get = MagicMock(
            return_value=MockResponse("safe")
        )

        result = plugin.run(mock_context)

        # Check if any time-based SLEEP payload was sent
        calls = mock_context.scan_context.http_client.get.call_args_list
        time_payload_sent = any("SLEEP" in str(call) for call in calls)
        assert time_payload_sent
