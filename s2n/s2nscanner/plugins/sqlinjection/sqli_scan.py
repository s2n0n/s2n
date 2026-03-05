import json
import uuid
import time
import requests
from pathlib import Path
from typing import Dict, List, Optional
from bs4 import BeautifulSoup
import requests.compat

from s2n.s2nscanner.clients.http_client import HttpClient
from s2n.s2nscanner.interfaces import (
    PluginContext,
    Finding,
    Severity,
    Confidence,
)
from s2n.s2nscanner.logger import get_logger
from s2n.s2nscanner.plugins.sqlinjection.sqli_config import (
    TEST_PAYLOAD_TIME_BLIND,
    TIME_THRESHOLD,
)
from s2n.s2nscanner.plugins.sqlinjection.sqli_dvwa_helper import (
    check_for_success_indicator,
    check_for_error_indicator,
    extract_url_info,
)
from s2n.s2nscanner.crawler import crawl_recursive

logger = get_logger("plugins.sqlinjection")


# --- JSON 페이로드 로딩 ---
def _load_sqli_payloads() -> Dict[str, List[str]]:
    """sqli_payloads.json에서 SQL 인젝션 페이로드를 로드합니다."""
    payload_path = Path(__file__).parent / "sqli_payloads.json"
    if not payload_path.exists():
        # JSON 파일이 없으면 기존 하드코딩 페이로드로 폴백
        return {
            "error_boolean": ["' OR '1'='1' -- "],
            "time_based": [TEST_PAYLOAD_TIME_BLIND],
        }

    with payload_path.open("r", encoding="utf-8") as fp:
        data = json.load(fp)

    error_boolean: List[str] = []
    time_based: List[str] = []

    def walk(node, target: List[str]):
        if isinstance(node, list):
            for item in node:
                walk(item, target)
        elif isinstance(node, dict):
            for value in node.values():
                walk(value, target)
        elif isinstance(node, str):
            target.append(node)

    payloads = data.get("payloads", {})

    # 구조 통일: payloads.* 기준으로 읽되, 기존 top-level 구조도 호환
    error_sections = (
        "error_based",
        "boolean_based",
        "union_based",
        "stacked_queries",
        "filter_bypass",
        "waf_bypass",
        "korean_encoding_specific",
    )
    for section in error_sections:
        walk(payloads.get(section, data.get(section, {})), error_boolean)

    walk(payloads.get("time_based", data.get("time_based", {})), time_based)

    loaded = {
        "error_boolean": [p for p in error_boolean if p],
        "time_based": [p for p in time_based if p],
    }
    logger.info(
        "[*] SQLi payloads loaded: error/boolean=%d, time_based=%d",
        len(loaded["error_boolean"]),
        len(loaded["time_based"]),
    )
    return loaded


SQLI_PAYLOADS = _load_sqli_payloads()


def sqli_scan(
    target_url: str,
    depth: int,
    timeout: int,
    http_client: Optional[HttpClient] = None,
    plugin_context: Optional[PluginContext] = None,
) -> List[Finding]:
    """
    Scans the target URL for SQL Injection vulnerabilities.
    """
    results: List[Finding] = []
    context_logger = getattr(plugin_context, "logger", None) or logger

    # Ensure http_client is available
    if http_client is None:
        context_logger.error("HttpClient is required for sqli_scan.")
        return results

    try:
        base_url, get_params_from_url = extract_url_info(target_url)
    except Exception as e:
        context_logger.error(f"URL parsing error: {e}")
        return results

    # 1. Scan GET parameters
    targets = crawl_recursive(base_url, http_client, depth=depth, timeout=timeout) or [base_url]
    total_targets = len(targets)
    context_logger.info(f"[*] Discovered {total_targets} URLs to scan for SQL injection")

    for idx, target in enumerate(targets, 1):
        context_logger.info(f"[*] Scanning URL {idx}/{total_targets}: {target}")
        get_findings = _scan_get_param(http_client, base_url, target, get_params_from_url)
        results.extend(get_findings)
        form_findings = _scan_forms(http_client, target)
        results.extend(form_findings)

    return results


def _create_finding(
    vul_type: str,
    severity: Severity,
    url: str,
    payload: Optional[str],
    method: str,
    param: str,
    details: str,
) -> Finding:
    title_map = {
        "SQL Injection (Data Retrieval/Boolean)": "SQL Injection (Data Exposure)",
        "SQL Injection (Error Based)": "SQL Injection (Error Message)",
        "SQL Injection (Time Based)": "SQL Injection (Blind)",
    }

    return Finding(
        id=str(uuid.uuid4()),
        plugin="sqlinjection",
        severity=severity,
        title=title_map.get(vul_type, "SQL Injection Detected"),
        description=f"URL: {url}에서 {method} 요청의 파라미터 '{param}'에서 {vul_type} 징후가 발견되었습니다. 상세: {details}",
        url=url,
        method=method,
        parameter=param,
        payload=payload if payload else None,
        evidence=details,
        confidence=Confidence.FIRM,
    )


def _scan_get_param(
    client: HttpClient, base_url: str, full_url: str, param_names: List[str]
) -> List[Finding]:
    vulnerabilities = []

    for param in param_names:
        first_finding = _find_get_error_or_boolean(client, base_url, full_url, param)
        if first_finding:
            vulnerabilities.append(first_finding)
            continue

        time_finding = _find_get_time_based(client, base_url, full_url, param)
        if time_finding:
            vulnerabilities.append(time_finding)

    return vulnerabilities


def _scan_forms(client: HttpClient, url: str) -> List[Finding]:
    vulnerabilities = []

    try:
        response = client.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
    except Exception as e:
        logger.debug(f"Form page request error: {e}")
        return []

    for form in forms:
        method = form.get("method", "GET").upper()
        form_url = requests.compat.urljoin(url, form.get("action", url))
        input_fields = form.find_all(["input", "textarea", "select"])
        param_names = [field.get("name") for field in input_fields if field.get("name")]

        if not param_names:
            continue

        for param in param_names:
            first_finding = _find_form_error_or_boolean(
                client,
                form_url,
                method,
                param_names,
                param,
            )
            if first_finding:
                vulnerabilities.append(first_finding)
                continue

            time_finding = _find_form_time_based(
                client,
                form_url,
                method,
                param_names,
                param,
            )
            if time_finding:
                vulnerabilities.append(time_finding)

    return vulnerabilities


def _find_get_error_or_boolean(
    client: HttpClient,
    base_url: str,
    full_url: str,
    param: str,
) -> Optional[Finding]:
    for payload in SQLI_PAYLOADS["error_boolean"]:
        attack_url = f"{base_url}?{param}={payload}"
        try:
            response = client.get(attack_url, timeout=5)
        except Exception as e:
            logger.debug(f"GET request error ({param}): {e}")
            continue

        success_indicator = check_for_success_indicator(response.text)
        if success_indicator:
            return _create_finding(
                "SQL Injection (Data Retrieval/Boolean)",
                Severity.HIGH,
                full_url,
                payload,
                "GET",
                param,
                f"성공 징후 '{success_indicator}' 발견",
            )

        error_indicator = check_for_error_indicator(response.text)
        if error_indicator:
            return _create_finding(
                "SQL Injection (Error Based)",
                Severity.HIGH,
                full_url,
                payload,
                "GET",
                param,
                f"에러 키워드 '{error_indicator}' 발견",
            )

    return None


def _find_get_time_based(
    client: HttpClient,
    base_url: str,
    full_url: str,
    param: str,
) -> Optional[Finding]:
    for payload in SQLI_PAYLOADS["time_based"]:
        attack_url = f"{base_url}?{param}={payload}"
        try:
            start_time = time.time()
            client.get(attack_url, timeout=10)
            elapsed_time = time.time() - start_time
        except Exception as e:
            logger.debug(f"GET (Time Blind) request error ({param}): {e}")
            continue

        if elapsed_time > TIME_THRESHOLD:
            return _create_finding(
                "SQL Injection (Time Based)",
                Severity.MEDIUM,
                full_url,
                payload,
                "GET",
                param,
                f"응답 시간 {elapsed_time:.2f}초 초과",
            )

    return None


def _send_form_request(
    client: HttpClient,
    method: str,
    form_url: str,
    form_data: Dict[str, str],
    timeout: int,
):
    if method == "POST":
        return client.post(
            form_url,
            data=form_data,
            timeout=timeout,
            allow_redirects=True,
        )

    return client.get(
        form_url,
        params=form_data,
        timeout=timeout,
        allow_redirects=True,
    )


def _find_form_error_or_boolean(
    client: HttpClient,
    form_url: str,
    method: str,
    param_names: List[str],
    param: str,
) -> Optional[Finding]:
    for payload in SQLI_PAYLOADS["error_boolean"]:
        test_data = {p: payload if p == param else "1" for p in param_names}

        try:
            response = _send_form_request(client, method, form_url, test_data, timeout=5)
        except Exception as e:
            logger.debug(f"Form request error ({method}/{param}): {e}")
            continue

        success_indicator = check_for_success_indicator(response.text)
        if success_indicator:
            return _create_finding(
                "SQL Injection (Data Retrieval/Boolean)",
                Severity.HIGH,
                form_url,
                payload,
                method,
                param,
                f"성공 징후 '{success_indicator}' 발견",
            )

        error_indicator = check_for_error_indicator(response.text)
        if error_indicator:
            return _create_finding(
                "SQL Injection (Error Based)",
                Severity.HIGH,
                form_url,
                payload,
                method,
                param,
                f"에러 키워드 '{error_indicator}' 발견",
            )

    return None


def _find_form_time_based(
    client: HttpClient,
    form_url: str,
    method: str,
    param_names: List[str],
    param: str,
) -> Optional[Finding]:
    for payload in SQLI_PAYLOADS["time_based"]:
        test_data = {p: payload if p == param else "1" for p in param_names}
        try:
            start_time = time.time()
            _send_form_request(client, method, form_url, test_data, timeout=10)
            elapsed_time = time.time() - start_time
        except Exception as e:
            logger.debug(f"Form (Time Blind) request error ({method}/{param}): {e}")
            continue

        if elapsed_time > TIME_THRESHOLD:
            return _create_finding(
                "SQL Injection (Time Based)",
                Severity.MEDIUM,
                form_url,
                payload,
                method,
                param,
                f"응답 시간 {elapsed_time:.2f}초 초과",
            )

    return None
