"""
autobot_driver.py
WebDriver 설정/정리 래퍼.
brute_force_selenium.py의 setup_driver 패턴을 재사용하되,
headless 모드 토글 및 봇 탐지 회피 옵션 없이 기본 headless 상태를 유지한다.
"""

import logging
import os
import sys

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager


def setup_driver(logger: logging.Logger, headless: bool = True) -> webdriver.Chrome:
    """
    Chromium WebDriver를 설정하고 반환한다.

    Args:
        logger: 로거 인스턴스
        headless: True이면 headless 모드로 실행

    Returns:
        설정된 Chrome WebDriver 인스턴스

    Raises:
        Exception: WebDriver 초기화 실패 시 예외를 그대로 전파
    """
    options = webdriver.ChromeOptions()

    if headless:
        options.add_argument("--headless")

    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_experimental_option("excludeSwitches", ["enable-logging"])
    options.add_argument("--log-level=3")

    log_path = "NUL" if sys.platform == "win32" else os.devnull

    logger.debug(f"WebDriver 초기화 중 (headless={headless})...")
    driver = webdriver.Chrome(
        service=Service(
            executable_path=ChromeDriverManager().install(),
            log_path=log_path,
        ),
        options=options,
    )
    logger.debug("WebDriver 초기화 완료.")
    return driver
