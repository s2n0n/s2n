import re
import uuid
from typing import List, Optional, Any

from s2n.s2nscanner.clients.http_client import HttpClient
from s2n.s2nscanner.interfaces import (
    PluginContext,
    Finding,
    HTTPRequest,
    Severity,
    Confidence,
)
from s2n.s2nscanner.plugins.csrf.csrf_constants import (
    CSRF_TOKEN_KEYWORDS,
    META_CSRF_NAMES,
    JS_TOKEN_PATTERN,
    SAMESITE_SECURE_VALUES,
    DEFAULT_TIMEOUT,
    USER_AGENT,
)
from s2n.s2nscanner.plugins.csrf.csrf_utils import FormParser, MetaTokenParser
from s2n.s2nscanner.logger import get_logger


logger = get_logger("plugins.csrf")


def csrf_scan(
    target_url: str,
    http_client: Optional[HttpClient] = None,
    plugin_context: Optional[PluginContext] = None,
) -> List[Finding]:
    """
    Multi-layer CSRF vulnerability scan (L1-L8).

    L1: Form token keyword presence
    L2: Token uniqueness (two GETs, compare values)
    L3: SameSite cookie + security header validation
    L4: Origin header validation (safe GET-only)
    L5: <meta> tag CSRF token scanning
    L6: <script> global JS variable CSRF token scanning
    L7: API custom header (X-Requested-With) requirement check
    L8: CORS misconfiguration analysis (integrated with L4)

    No state-changing requests are sent.
    """
    results: List[Finding] = []
    context_logger = getattr(plugin_context, "logger", None) or logger

    session = getattr(http_client, "s", None)
    if session is None:
        context_logger.error(
            "HTTPClient must expose an underlying session via attribute 's'."
        )
        return results
    if "User-Agent" not in session.headers:
        session.headers.update({"User-Agent": USER_AGENT})

    try:
        # Two GETs for token uniqueness comparison (L2, L5, L6)
        resp1 = session.get(target_url, timeout=DEFAULT_TIMEOUT)
        resp2 = session.get(target_url, timeout=DEFAULT_TIMEOUT)
        html1 = resp1.text
        html2 = resp2.text

        # L3: Header + SameSite cookie validation
        results.extend(scan_res_headers(resp1.headers, target_url))
        # L1 + L2: Form token presence + uniqueness
        results.extend(scan_form_tags(html1, html2, resp1, target_url))
        # L4 + L8: Origin validation + CORS misconfiguration
        results.extend(scan_origin_validation(session, target_url))
        # L5: Meta tag token scanning
        results.extend(scan_meta_tokens(html1, html2, target_url))
        # L6: JS global variable token scanning
        results.extend(scan_js_tokens(html1, html2, target_url))
        # L7: API custom header requirement
        results.extend(scan_custom_header_requirement(session, target_url))

    except Exception as e:
        context_logger.error("[csrf_scan] Error scanning %s: %s", target_url, e)

    return results


# ---------------------------------------------------------------------------
# L3: Response header + SameSite cookie validation
# ---------------------------------------------------------------------------

def scan_res_headers(headers: dict, target_url: str = "N/A") -> List[Finding]:
    """
    Validate CSRF-related response headers:
    - X-Frame-Options value (DENY / SAMEORIGIN)
    - Content-Security-Policy presence and safety
    - Set-Cookie SameSite attribute value
    """
    findings: List[Finding] = []

    # --- X-Frame-Options ---
    xfo = headers.get("X-Frame-Options", "")
    if not xfo:
        findings.append(_make_header_finding(
            target_url,
            Severity.MEDIUM,
            "Missing X-Frame-Options Header",
            "The X-Frame-Options header is absent, making the page susceptible to clickjacking.",
            "Missing: X-Frame-Options",
            Confidence.FIRM,
        ))
    elif xfo.upper() not in ("DENY", "SAMEORIGIN"):
        findings.append(_make_header_finding(
            target_url,
            Severity.LOW,
            "Weak X-Frame-Options Value",
            f"X-Frame-Options is set to '{xfo}', which may not provide adequate protection.",
            f"X-Frame-Options: {xfo}",
            Confidence.TENTATIVE,
        ))

    # --- Content-Security-Policy ---
    csp = headers.get("Content-Security-Policy", "")
    if not csp:
        findings.append(_make_header_finding(
            target_url,
            Severity.MEDIUM,
            "Missing Content-Security-Policy Header",
            "No CSP header found. A proper CSP helps mitigate XSS and data injection attacks.",
            "Missing: Content-Security-Policy",
            Confidence.FIRM,
        ))
    elif "*" in csp or "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
        findings.append(_make_header_finding(
            target_url,
            Severity.LOW,
            "Weak Content-Security-Policy Directives",
            "CSP contains wildcard or unsafe directives that weaken its protection.",
            f"CSP: {csp[:200]}",
            Confidence.FIRM,
        ))

    # --- Set-Cookie SameSite ---
    set_cookie = headers.get("Set-Cookie", "")
    if set_cookie:
        findings.extend(_check_samesite_cookies(set_cookie, target_url))

    # If nothing was found, emit an INFO finding
    if not findings:
        findings.append(_make_header_finding(
            target_url,
            Severity.INFO,
            "CSRF Protection Headers Adequate",
            "Response headers include appropriate CSRF-related protections.",
            "All checked headers present with acceptable values.",
            Confidence.TENTATIVE,
        ))

    return findings


def _check_samesite_cookies(set_cookie_header: str, target_url: str) -> List[Finding]:
    """Parse Set-Cookie header(s) and validate SameSite values."""
    findings: List[Finding] = []
    cookies = set_cookie_header.split(",") if "," in set_cookie_header else [set_cookie_header]

    for cookie in cookies:
        cookie_lower = cookie.lower().strip()
        if not cookie_lower:
            continue

        cookie_name = cookie.strip().split("=")[0].strip() if "=" in cookie else "unknown"

        if "samesite" not in cookie_lower:
            findings.append(_make_header_finding(
                target_url,
                Severity.MEDIUM,
                f"Cookie '{cookie_name}' Missing SameSite Attribute",
                f"The cookie '{cookie_name}' does not set a SameSite attribute, "
                "making it vulnerable to cross-site request attachment.",
                f"Set-Cookie: {cookie.strip()[:200]}",
                Confidence.FIRM,
            ))
        else:
            samesite_value = _extract_samesite_value(cookie_lower)
            if samesite_value and samesite_value not in SAMESITE_SECURE_VALUES:
                findings.append(_make_header_finding(
                    target_url,
                    Severity.HIGH,
                    f"Cookie '{cookie_name}' Has SameSite=None",
                    f"SameSite=None on '{cookie_name}' means the cookie is sent on "
                    "cross-origin requests, offering no CSRF protection from this mechanism.",
                    f"SameSite={samesite_value}",
                    Confidence.CERTAIN,
                ))

    return findings


def _extract_samesite_value(cookie_lower: str) -> str:
    """Extract the SameSite value from a lowercased cookie string."""
    for part in cookie_lower.split(";"):
        part = part.strip()
        if part.startswith("samesite"):
            if "=" in part:
                return part.split("=", 1)[1].strip()
    return ""


def _make_header_finding(
    url: str,
    severity: Severity,
    title: str,
    description: str,
    evidence: str,
    confidence: Confidence,
) -> Finding:
    """Helper to build a header-related Finding."""
    return Finding(
        id=str(uuid.uuid4()),
        plugin="csrf",
        severity=severity,
        title=title,
        description=description,
        url=url,
        evidence=evidence,
        request=None,
        response=None,
        remediation=(
            "Configure appropriate security headers: "
            "X-Frame-Options (DENY or SAMEORIGIN), CSP without unsafe directives, "
            "and SameSite=Strict or Lax on session cookies."
        ),
        references=[
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
        cwe_id="CWE-352",
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# L1 + L2: Form token presence + uniqueness
# ---------------------------------------------------------------------------

def scan_form_tags(
    html1: str,
    html2: str,
    resp: Any,
    target_url: str,
) -> List[Finding]:
    """
    Validate forms for CSRF tokens (L1) and check token uniqueness (L2).

    - GET forms get LOW severity (not state-changing).
    - POST/PUT/DELETE/PATCH forms get HIGH severity if token missing.
    - If token exists but value is identical across two responses, warn about static tokens.
    """
    findings: List[Finding] = []

    try:
        parser1 = FormParser()
        parser1.feed(html1 or "")
        forms1 = parser1.forms

        parser2 = FormParser()
        parser2.feed(html2 or "")
        forms2 = parser2.forms
    except Exception:
        forms1 = []
        forms2 = []

    if not forms1:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            plugin="csrf",
            severity=Severity.INFO,
            title="No Form Tags Found",
            description="No <form> tags were found on the page.",
            url=target_url,
            evidence="No <form> tags present in response HTML.",
            request=_build_request(resp, target_url),
            response=None,
            confidence=Confidence.TENTATIVE,
        ))
        return findings

    for idx, form in enumerate(forms1):
        form_method = (form.get("attrs", {}).get("method", "get")).upper()
        inputs = form.get("inputs", [])
        is_state_changing = form_method in ("POST", "PUT", "DELETE", "PATCH")

        # L1: Check for token-like hidden input
        token_input = _find_token_input(inputs)

        if token_input is None:
            severity = Severity.HIGH if is_state_changing else Severity.LOW
            snippet = _form_snippet(form)
            findings.append(Finding(
                id=str(uuid.uuid4()),
                plugin="csrf",
                severity=severity,
                title=f"Form #{idx + 1} ({form_method}) Missing CSRF Token",
                description=(
                    f"A {form_method} form does not include an anti-CSRF token. "
                    + ("This form performs state-changing actions and is vulnerable to CSRF."
                       if is_state_changing
                       else "This GET form is lower risk but should still be reviewed.")
                ),
                url=target_url,
                evidence=f"Form snippet: {snippet}",
                request=_build_request(resp, target_url),
                response=None,
                remediation=(
                    "Add a server-validated anti-CSRF token (synchronizer token pattern) "
                    "to all state-changing forms."
                ),
                references=[
                    "https://owasp.org/www-community/attacks/csrf",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                ],
                cwe_id="CWE-352",
                cvss_score=6.8 if is_state_changing else 3.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" if is_state_changing else None,
                confidence=Confidence.FIRM if is_state_changing else Confidence.TENTATIVE,
            ))
        else:
            # L2: Token found -- check uniqueness across two requests
            token_value1 = token_input.get("value", "")
            token_name = token_input.get("name", "")

            token_value2 = _get_token_value_from_forms(forms2, idx, token_name)

            if token_value1 and token_value2 and token_value1 == token_value2:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    plugin="csrf",
                    severity=Severity.MEDIUM,
                    title=f"Form #{idx + 1} Has Static CSRF Token",
                    description=(
                        f"The CSRF token '{token_name}' has the same value across two "
                        "separate requests. Static tokens offer weaker protection against CSRF."
                    ),
                    url=target_url,
                    evidence=f"Token '{token_name}' value unchanged: {token_value1[:60]}",
                    request=_build_request(resp, target_url),
                    response=None,
                    remediation="Generate a unique, unpredictable CSRF token per session or per request.",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                    ],
                    cwe_id="CWE-352",
                    confidence=Confidence.FIRM,
                ))

    # If no issues found, emit an INFO
    if not findings:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            plugin="csrf",
            severity=Severity.INFO,
            title="Forms Include CSRF Tokens",
            description="All detected <form> elements include anti-CSRF tokens with unique values.",
            url=target_url,
            evidence="CSRF token-like inputs found in all forms.",
            request=_build_request(resp, target_url),
            response=None,
            confidence=Confidence.TENTATIVE,
        ))

    return findings


def _find_token_input(inputs: list) -> Optional[dict]:
    """Find a hidden input that looks like a CSRF token."""
    for inp in inputs:
        name = inp.get("name", "").lower()
        idv = inp.get("id", "").lower()
        itype = inp.get("type", "").lower()

        if itype == "hidden" and any(
            k.lower() in name or k.lower() in idv for k in CSRF_TOKEN_KEYWORDS
        ):
            return inp

        if any(k.lower() in name for k in CSRF_TOKEN_KEYWORDS) or any(
            k.lower() in idv for k in CSRF_TOKEN_KEYWORDS
        ):
            return inp
    return None


def _get_token_value_from_forms(forms: list, form_idx: int, token_name: str) -> str:
    """Get the token value from the same form index in a second parse result."""
    if form_idx >= len(forms):
        return ""
    inputs = forms[form_idx].get("inputs", [])
    for inp in inputs:
        if inp.get("name", "").lower() == token_name.lower():
            return inp.get("value", "")
    return ""


def _form_snippet(form: dict) -> str:
    """Return a truncated HTML snippet of a form."""
    html = form.get("html", "") if isinstance(form, dict) else str(form)
    return (html[:300] + "...") if html and len(html) > 300 else html


def _build_request(resp: Any, target_url: str) -> Optional[HTTPRequest]:
    """Safely build an HTTPRequest from a response object."""
    try:
        return HTTPRequest(
            method="GET",
            url=target_url,
            headers=dict(resp.request.headers)
            if hasattr(resp, "request") and hasattr(resp.request, "headers")
            else {},
            body=None,
            cookies=dict(resp.request._cookies)
            if hasattr(resp, "request") and hasattr(resp.request, "_cookies")
            else {},
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# L4 + L8: Origin validation + CORS misconfiguration
# ---------------------------------------------------------------------------

def scan_origin_validation(session: Any, target_url: str) -> List[Finding]:
    """
    L4: Test whether the server validates the Origin header.
    L8: Check for CORS misconfiguration in the spoofed-origin response.

    Safe: only GET requests are sent.
    """
    findings: List[Finding] = []
    spoofed_origin = "https://evil.example.com"

    try:
        normal_resp = session.get(target_url, timeout=DEFAULT_TIMEOUT)
        spoofed_resp = session.get(
            target_url,
            timeout=DEFAULT_TIMEOUT,
            headers={"Origin": spoofed_origin},
        )

        # --- L4: Origin not validated ---
        if (
            hasattr(normal_resp, "status_code")
            and hasattr(spoofed_resp, "status_code")
            and normal_resp.status_code == spoofed_resp.status_code == 200
        ):
            normal_len = len(getattr(normal_resp, "text", ""))
            spoofed_len = len(getattr(spoofed_resp, "text", ""))
            if normal_len > 0 and abs(normal_len - spoofed_len) / normal_len < 0.1:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    plugin="csrf",
                    severity=Severity.MEDIUM,
                    title="Server Does Not Validate Origin Header",
                    description=(
                        "A request with a spoofed Origin header received the same response "
                        "as a normal request. The server may not validate the Origin header."
                    ),
                    url=target_url,
                    evidence=(
                        f"Normal: {normal_resp.status_code} ({normal_len}B), "
                        f"Spoofed: {spoofed_resp.status_code} ({spoofed_len}B)"
                    ),
                    request=HTTPRequest(
                        method="GET", url=target_url,
                        headers={"Origin": spoofed_origin},
                    ),
                    response=None,
                    remediation=(
                        "Validate Origin/Referer headers on state-changing endpoints "
                        "and reject requests from untrusted origins."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#verifying-origin-with-standard-headers",
                    ],
                    cwe_id="CWE-346",
                    confidence=Confidence.TENTATIVE,
                ))

        # --- L8: CORS misconfiguration ---
        spoofed_headers = getattr(spoofed_resp, "headers", {})
        if isinstance(spoofed_headers, dict):
            findings.extend(_check_cors_headers(spoofed_headers, spoofed_origin, target_url))

    except Exception as e:
        logger.debug("Origin/CORS check skipped for %s: %s", target_url, e)

    return findings


def _check_cors_headers(
    headers: dict,
    spoofed_origin: str,
    target_url: str,
) -> List[Finding]:
    """L8: Analyze CORS headers from a spoofed-origin response."""
    findings: List[Finding] = []
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "").lower()

    if not acao:
        return findings

    # Case 1: Wildcard ACAO + credentials
    if acao == "*" and acac == "true":
        findings.append(Finding(
            id=str(uuid.uuid4()),
            plugin="csrf",
            severity=Severity.HIGH,
            title="CORS Wildcard With Credentials",
            description=(
                "Access-Control-Allow-Origin is '*' and Access-Control-Allow-Credentials "
                "is 'true'. This combination allows any origin to make credentialed "
                "cross-origin requests, enabling CSRF and data theft."
            ),
            url=target_url,
            evidence=f"ACAO: {acao}, ACAC: {acac}",
            remediation=(
                "Never combine Access-Control-Allow-Origin: * with "
                "Access-Control-Allow-Credentials: true. Whitelist specific trusted origins."
            ),
            references=[
                "https://portswigger.net/web-security/cors",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
            ],
            cwe_id="CWE-942",
            cvss_score=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            confidence=Confidence.CERTAIN,
        ))

    # Case 2: Server echoes the spoofed origin back
    elif acao.lower() == spoofed_origin.lower():
        severity = Severity.HIGH if acac == "true" else Severity.MEDIUM
        findings.append(Finding(
            id=str(uuid.uuid4()),
            plugin="csrf",
            severity=severity,
            title="CORS Origin Reflection" + (" With Credentials" if acac == "true" else ""),
            description=(
                f"The server reflected the spoofed Origin '{spoofed_origin}' in the "
                "Access-Control-Allow-Origin header"
                + (". Combined with Allow-Credentials: true, this allows "
                   "credentialed cross-origin requests from any origin."
                   if acac == "true"
                   else ". While credentials are not allowed, this may indicate "
                   "an overly permissive CORS policy.")
            ),
            url=target_url,
            evidence=f"ACAO: {acao}, ACAC: {acac or 'not set'}",
            remediation=(
                "Do not blindly reflect the Origin header. Maintain a whitelist "
                "of trusted origins and validate against it."
            ),
            references=[
                "https://portswigger.net/web-security/cors",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
            ],
            cwe_id="CWE-942",
            cvss_score=8.1 if acac == "true" else 5.3,
            confidence=Confidence.CERTAIN if acac == "true" else Confidence.FIRM,
        ))

    # Case 3: Wildcard without credentials (lower risk)
    elif acao == "*":
        findings.append(Finding(
            id=str(uuid.uuid4()),
            plugin="csrf",
            severity=Severity.LOW,
            title="CORS Allows All Origins",
            description=(
                "Access-Control-Allow-Origin is set to '*'. While credentials are not "
                "included, this allows any site to read responses from this endpoint."
            ),
            url=target_url,
            evidence=f"ACAO: {acao}",
            remediation="Restrict ACAO to specific trusted origins if the endpoint serves sensitive data.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
            cwe_id="CWE-942",
            confidence=Confidence.FIRM,
        ))

    return findings


# ---------------------------------------------------------------------------
# L5: <meta> tag CSRF token scanning
# ---------------------------------------------------------------------------

def scan_meta_tokens(html1: str, html2: str, target_url: str) -> List[Finding]:
    """
    Scan HTML for CSRF tokens embedded in <meta> tags
    (e.g. Rails csrf-token, Laravel csrf-token).

    Compares values across two responses to detect static tokens.
    """
    findings: List[Finding] = []

    tokens1 = _parse_meta_tokens(html1)
    tokens2 = _parse_meta_tokens(html2)

    if not tokens1:
        # No meta tokens found -- not necessarily a problem if forms have tokens
        return findings

    for t1 in tokens1:
        name = t1["name"]
        value1 = t1["content"]

        # Find matching token in second response
        value2 = ""
        for t2 in tokens2:
            if t2["name"].lower() == name.lower():
                value2 = t2["content"]
                break

        if not value1:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                plugin="csrf",
                severity=Severity.MEDIUM,
                title=f"Meta CSRF Token '{name}' Has Empty Value",
                description=f"<meta name=\"{name}\"> exists but content is empty.",
                url=target_url,
                evidence=f"<meta name=\"{name}\" content=\"\">",
                remediation="Ensure the meta tag CSRF token is populated with a valid, unique value.",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                ],
                cwe_id="CWE-352",
                confidence=Confidence.FIRM,
            ))
        elif value2 and value1 == value2:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                plugin="csrf",
                severity=Severity.MEDIUM,
                title=f"Meta CSRF Token '{name}' Is Static",
                description=(
                    f"<meta name=\"{name}\"> has the same value across two requests. "
                    "Static tokens offer weaker CSRF protection."
                ),
                url=target_url,
                evidence=f"Token value unchanged: {value1[:60]}",
                remediation="Generate unique CSRF tokens per session or per request.",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                ],
                cwe_id="CWE-352",
                confidence=Confidence.FIRM,
            ))

    return findings


def _parse_meta_tokens(html: str) -> list:
    """Extract CSRF-related meta tags from HTML."""
    parser = MetaTokenParser(META_CSRF_NAMES)
    try:
        parser.feed(html or "")
    except Exception:
        pass
    return parser.tokens


# ---------------------------------------------------------------------------
# L6: <script> global JS variable CSRF token scanning
# ---------------------------------------------------------------------------

def scan_js_tokens(html1: str, html2: str, target_url: str) -> List[Finding]:
    """
    Scan HTML <script> blocks for CSRF tokens assigned to global JS variables.

    Compares values across two responses to detect static tokens.
    """
    findings: List[Finding] = []

    matches1 = re.findall(JS_TOKEN_PATTERN, html1 or "", re.IGNORECASE)
    matches2 = re.findall(JS_TOKEN_PATTERN, html2 or "", re.IGNORECASE)

    if not matches1:
        return findings

    for i, value1 in enumerate(matches1):
        value2 = matches2[i] if i < len(matches2) else ""

        if value2 and value1 == value2:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                plugin="csrf",
                severity=Severity.MEDIUM,
                title="JS Global CSRF Token Is Static",
                description=(
                    "A CSRF token assigned to a JavaScript variable has the same value "
                    "across two separate requests. Static tokens weaken CSRF protection."
                ),
                url=target_url,
                evidence=f"JS token value unchanged: {value1[:60]}",
                remediation="Generate unique CSRF tokens per session or per request.",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                ],
                cwe_id="CWE-352",
                confidence=Confidence.FIRM,
            ))

    return findings


# ---------------------------------------------------------------------------
# L7: API custom header requirement
# ---------------------------------------------------------------------------

def scan_custom_header_requirement(session: Any, target_url: str) -> List[Finding]:
    """
    Check whether the server differentiates between requests with and without
    the X-Requested-With header.

    If both responses are identical (200, similar body), the server likely does
    not require a custom header for CSRF protection.

    Safe: GET requests only.
    """
    findings: List[Finding] = []

    try:
        resp_with = session.get(
            target_url,
            timeout=DEFAULT_TIMEOUT,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        resp_without = session.get(target_url, timeout=DEFAULT_TIMEOUT)

        if (
            hasattr(resp_with, "status_code")
            and hasattr(resp_without, "status_code")
            and resp_with.status_code == resp_without.status_code == 200
        ):
            len_with = len(getattr(resp_with, "text", ""))
            len_without = len(getattr(resp_without, "text", ""))
            if len_with > 0 and abs(len_with - len_without) / len_with < 0.1:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    plugin="csrf",
                    severity=Severity.LOW,
                    title="Server Does Not Require X-Requested-With Header",
                    description=(
                        "Responses with and without the X-Requested-With header are identical. "
                        "The server does not appear to use custom header validation as a CSRF defense."
                    ),
                    url=target_url,
                    evidence=(
                        f"With header: {resp_with.status_code} ({len_with}B), "
                        f"Without: {resp_without.status_code} ({len_without}B)"
                    ),
                    request=HTTPRequest(
                        method="GET", url=target_url,
                        headers={"X-Requested-With": "XMLHttpRequest"},
                    ),
                    response=None,
                    remediation=(
                        "For API endpoints, consider requiring X-Requested-With or a custom "
                        "header and rejecting requests that lack it."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#use-of-custom-request-headers",
                    ],
                    cwe_id="CWE-352",
                    confidence=Confidence.TENTATIVE,
                ))

    except Exception as e:
        logger.debug("Custom header check skipped for %s: %s", target_url, e)

    return findings
