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
            return MockResponse("ID: 1, admin")
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
        auth_config=SimpleNamespace(auth_adapter=None),
    )
    logger = get_logger()
    return SimpleNamespace(scan_context=scan_context, logger=logger)


def test_sqli_plugin_detects_boolean_based(mock_context):
    plugin = SQLInjectionPlugin()
    result = plugin.run(mock_context)

    assert result.status == PluginStatus.PARTIAL
    assert len(result.findings) > 0
    finding = result.findings[0]
    assert "SQL Injection" in finding.title
    assert finding.payload


def test_sqli_plugin_sends_sleep_payload(mock_context):
    # 시간 기반 페이로드 전송 여부를 검증
    plugin = SQLInjectionPlugin()

    with (
        patch("s2n.s2nscanner.plugins.sqlinjection.sqli_scan.crawl_recursive") as mock_crawl,
        patch("s2n.s2nscanner.plugins.sqlinjection.sqli_scan.time.time") as mock_time,
    ):
        mock_crawl.return_value = ["http://example.com/page.php"]

        # 호출 횟수 변화와 무관하게 항상 elapsed > TIME_THRESHOLD가 되도록 설정
        timeline = {"current": 0.0}

        def _time_tick():
            timeline["current"] += 1.0
            return timeline["current"]

        mock_time.side_effect = _time_tick

        mock_context.scan_context.http_client.get = MagicMock(
            return_value=MockResponse("safe")
        )

        plugin.run(mock_context)

        calls = mock_context.scan_context.http_client.get.call_args_list
        time_keywords = (
            "sleep",
            "waitfor delay",
            "pg_sleep",
            "randomblob",
            "dbms_pipe.receive_message",
            "benchmark(",
        )
        time_payload_sent = any(
            any(keyword in str(call).lower() for keyword in time_keywords)
            for call in calls
        )
        assert time_payload_sent
