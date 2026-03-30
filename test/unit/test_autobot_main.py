from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from s2n.s2nscanner.interfaces import PluginStatus, Finding, PluginError
from s2n.s2nscanner.plugins.autobot.autobot_main import AutobotPlugin, main
from s2n.s2nscanner.plugins.autobot.autobot_behaviors import BehaviorResult

@pytest.fixture
def fake_scan_context():
    return SimpleNamespace(
        config=SimpleNamespace(target_url="http://target/app", accept_risk=False)
    )

@pytest.fixture
def fake_plugin_context(fake_scan_context):
    return SimpleNamespace(
        plugin_name="autobot",
        scan_context=fake_scan_context,
        plugin_config=SimpleNamespace(custom_params={}),
        logger=logging.getLogger("test_logger")
    )


def test_autobot_init():
    config = SimpleNamespace(custom_params={"behaviors": ["test1"], "block_threshold": 2, "headless": False})
    plugin = AutobotPlugin(config)
    assert plugin.behavior_names == ["test1"]
    assert plugin.block_threshold == 2
    assert plugin.headless is False
    assert plugin.request_delay_ms == 0


def test_request_user_confirmation_accept_risk(fake_plugin_context):
    plugin = AutobotPlugin()
    fake_plugin_context.scan_context.config.accept_risk = True
    assert plugin._request_user_confirmation(fake_plugin_context) is True


@patch("builtins.input", side_effect=["y"])
def test_request_user_confirmation_yes(mock_input, fake_plugin_context):
    plugin = AutobotPlugin()
    assert plugin._request_user_confirmation(fake_plugin_context) is True


@patch("builtins.input", side_effect=["n"])
def test_request_user_confirmation_no(mock_input, fake_plugin_context):
    plugin = AutobotPlugin()
    assert plugin._request_user_confirmation(fake_plugin_context) is False


@patch("s2n.s2nscanner.plugins.autobot.autobot_main.helper.resolve_target_url", return_value="http://target/app")
@patch("s2n.s2nscanner.plugins.autobot.autobot_main.setup_driver")
@patch("s2n.s2nscanner.plugins.autobot.autobot_main.load_behaviors")
def test_run_success_with_findings(mock_load_behaviors, mock_setup_driver, mock_resolve_target_url, fake_plugin_context):
    plugin = AutobotPlugin()
    fake_plugin_context.scan_context.config.accept_risk = True

    # 1. Provide mock behavior results (Not blocked = finding generated)
    mock_behavior_1 = Mock()
    mock_behavior_1.name = "rapid_crawl"
    mock_behavior_1.execute.return_value = BehaviorResult(
        behavior_name="rapid_crawl", was_blocked=False, evidence="No block detected", requests_sent=10
    )

    mock_load_behaviors.return_value = [mock_behavior_1]

    # 2. Run
    result = plugin.run(fake_plugin_context)

    # 3. Assert status and finding
    assert result.status == PluginStatus.SUCCESS
    assert len(result.findings) == 1
    assert result.findings[0].plugin == "autobot"
    assert result.findings[0].severity.name == "HIGH"
    assert "rapid_crawl" in result.findings[0].description
    assert result.requests_sent == 10


@patch("s2n.s2nscanner.plugins.autobot.autobot_main.helper.resolve_target_url", return_value="http://target/app")
@patch("s2n.s2nscanner.plugins.autobot.autobot_main.setup_driver")
@patch("s2n.s2nscanner.plugins.autobot.autobot_main.load_behaviors")
def test_run_success_no_findings(mock_load_behaviors, mock_setup_driver, mock_resolve_target_url, fake_plugin_context):
    plugin = AutobotPlugin()
    fake_plugin_context.scan_context.config.accept_risk = True

    # 1. Provide mock behavior results (Blocked = PASS, no finding)
    mock_behavior_1 = Mock()
    mock_behavior_1.name = "rapid_crawl"
    mock_behavior_1.execute.return_value = BehaviorResult(
        behavior_name="rapid_crawl", was_blocked=True, evidence="Blocked Detected", requests_sent=1
    )

    mock_load_behaviors.return_value = [mock_behavior_1]

    # 2. Run
    result = plugin.run(fake_plugin_context)

    # 3. Assert status and finding
    assert result.status == PluginStatus.SUCCESS
    assert len(result.findings) == 0


@patch("s2n.s2nscanner.plugins.autobot.autobot_main.helper.resolve_target_url", side_effect=ValueError("No url"))
def test_run_missing_target_url(mock_resolve_target_url, fake_plugin_context):
    plugin = AutobotPlugin()
    result = plugin.run(fake_plugin_context)
    assert result.status == PluginStatus.FAILED
    assert result.error.error_type == "ConfigurationError"


@patch("s2n.s2nscanner.plugins.autobot.autobot_main.helper.resolve_target_url", return_value="http://target/app")
@patch("s2n.s2nscanner.plugins.autobot.autobot_main.setup_driver", side_effect=Exception("Driver failed"))
@patch("s2n.s2nscanner.plugins.autobot.autobot_main.load_behaviors", return_value=["dummy_behavior"])
def test_run_driver_init_failure(mock_load_behaviors, mock_setup_driver, mock_resolve_target_url, fake_plugin_context):
    plugin = AutobotPlugin()
    fake_plugin_context.scan_context.config.accept_risk = True
    result = plugin.run(fake_plugin_context)
    assert result.status == PluginStatus.FAILED
    assert result.error.error_type == "DriverInitError"
