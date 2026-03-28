import pytest
from unittest.mock import Mock, patch

from s2n.s2nscanner.plugins.autobot.autobot_detector import (
    _check_http_status,
    _check_captcha_keywords,
    _check_domain_redirect,
    _check_block_title,
    is_blocked,
    get_evidence_snippet,
)


@pytest.fixture
def mock_driver():
    driver = Mock()
    driver.execute_script.return_value = None
    driver.page_source = "<html><body>Some content</body></html>"
    driver.current_url = "http://target.com/path"
    driver.title = "Target Page"
    return driver


def test_check_http_status(mock_driver):
    mock_driver.execute_script.return_value = 403
    blocked, reason = _check_http_status(mock_driver)
    assert blocked is True
    assert "HTTP 403" in reason

    mock_driver.execute_script.return_value = 429
    blocked, reason = _check_http_status(mock_driver)
    assert blocked is True
    assert "HTTP 429" in reason

    mock_driver.execute_script.return_value = 200
    blocked, reason = _check_http_status(mock_driver)
    assert blocked is False
    assert reason == ""


def test_check_captcha_keywords():
    blocked, reason = _check_captcha_keywords("Please verify you are human to continue.")
    assert blocked is True
    assert "verify you are human" in reason

    blocked, reason = _check_captcha_keywords("Welcome to our site.")
    assert blocked is False
    assert reason == ""


def test_check_domain_redirect(mock_driver):
    # Same domain
    blocked, reason = _check_domain_redirect(mock_driver, "http://target.com/start")
    assert blocked is False

    # Different domain
    mock_driver.current_url = "https://challenge.cloudflare.com/target"
    blocked, reason = _check_domain_redirect(mock_driver, "http://target.com/start")
    assert blocked is True
    assert "cloudflare.com" in reason


def test_check_block_title(mock_driver):
    mock_driver.title = "Access Denied"
    blocked, reason = _check_block_title(mock_driver)
    assert blocked is True
    assert "Access Denied" in reason

    mock_driver.title = "Normal Page"
    blocked, reason = _check_block_title(mock_driver)
    assert blocked is False


def test_is_blocked_hierarchy(mock_driver):
    # 1. HTTP Status takes precedence
    mock_driver.execute_script.return_value = 403
    mock_driver.page_source = "Clean page"
    blocked, reason = is_blocked(mock_driver)
    assert blocked is True
    assert "HTTP 403" in reason

    # 2. Captcha keyword
    mock_driver.execute_script.return_value = 200
    mock_driver.page_source = "recaptcha loaded here"
    blocked, reason = is_blocked(mock_driver)
    assert blocked is True
    assert "recaptcha" in reason

    # 3. None matched
    mock_driver.execute_script.return_value = 200
    mock_driver.page_source = "Clean page"
    mock_driver.title = "Clean Title"
    blocked, reason = is_blocked(mock_driver)
    assert blocked is False
    assert reason == "차단 신호 없음"


def test_get_evidence_snippet(mock_driver):
    mock_driver.page_source = "A" * 600
    snippet = get_evidence_snippet(mock_driver, max_length=500)
    assert len(snippet) == 500

    # Test fallback
    mock_driver.page_source = ""
    snippet = get_evidence_snippet(mock_driver)
    assert "URL: " in snippet
