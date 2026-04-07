"""
Sensitive File Exposure 스캔 로직

ATT&CK T1552.001 — Unsecured Credentials: Credentials In Files (Credential Access)

웹 루트에 실수로 노출된 환경 설정 파일, 백업 파일, 버전 관리 파일 등에서
API 키, DB 자격증명, 시크릿 토큰 등 민감 정보가 외부에서 읽힐 수 있는지 탐지한다.
"""
from __future__ import annotations

import re
import uuid
from typing import List, NamedTuple, Optional
from urllib.parse import urlparse, urljoin

from s2n.s2nscanner.clients.http_client import HttpClient
from s2n.s2nscanner.interfaces import (
    Confidence,
    Finding,
    PluginContext,
    Severity,
)
from s2n.s2nscanner.logger import get_logger

logger = get_logger("plugins.sensitive_files")


# ---------------------------------------------------------------------------
# 탐지 대상 파일 목록
# 각 항목: (path, severity, description)
# ---------------------------------------------------------------------------
class ProbeTarget(NamedTuple):
    path: str
    severity: Severity
    description: str


PROBE_TARGETS: List[ProbeTarget] = [
    # 환경 변수 / 시크릿 파일
    ProbeTarget(".env",                   Severity.CRITICAL, "Environment variable file"),
    ProbeTarget(".env.local",             Severity.CRITICAL, "Local environment file"),
    ProbeTarget(".env.production",        Severity.CRITICAL, "Production environment file"),
    ProbeTarget(".env.backup",            Severity.HIGH,     "Environment backup file"),
    ProbeTarget(".env.example",           Severity.LOW,      "Example environment file (may contain real secrets)"),
    # 버전 관리 시스템
    ProbeTarget(".git/config",            Severity.HIGH,     "Git repository configuration"),
    ProbeTarget(".git/HEAD",              Severity.MEDIUM,   "Git HEAD reference (confirms .git exposure)"),
    ProbeTarget(".svn/entries",           Severity.HIGH,     "SVN repository entries"),
    # CMS / 프레임워크 설정
    ProbeTarget("wp-config.php",          Severity.CRITICAL, "WordPress database credentials file"),
    ProbeTarget("wp-config.php.bak",      Severity.CRITICAL, "WordPress config backup"),
    ProbeTarget("config.php",             Severity.HIGH,     "PHP application config"),
    ProbeTarget("config/database.yml",    Severity.CRITICAL, "Rails database configuration"),
    ProbeTarget("config/secrets.yml",     Severity.CRITICAL, "Rails secrets file"),
    ProbeTarget("application.properties", Severity.HIGH,     "Spring Boot application properties"),
    ProbeTarget("application.yml",        Severity.HIGH,     "Spring Boot YAML configuration"),
    ProbeTarget("settings.py",            Severity.HIGH,     "Django settings file"),
    ProbeTarget("local_settings.py",      Severity.HIGH,     "Django local settings"),
    # 데이터베이스 백업
    ProbeTarget("backup.sql",             Severity.CRITICAL, "Database SQL backup"),
    ProbeTarget("dump.sql",               Severity.CRITICAL, "Database SQL dump"),
    ProbeTarget("database.sql",           Severity.CRITICAL, "Database SQL export"),
    ProbeTarget("db.sqlite3",             Severity.HIGH,     "SQLite database file"),
    # 인증서 / SSH 키
    ProbeTarget(".ssh/id_rsa",            Severity.CRITICAL, "SSH private key"),
    ProbeTarget("id_rsa",                 Severity.CRITICAL, "SSH private key (web root)"),
    ProbeTarget("server.key",             Severity.CRITICAL, "TLS/SSL private key"),
    # 접근 제어 파일
    ProbeTarget(".htpasswd",              Severity.HIGH,     "Apache HTTP Basic Auth credentials"),
    ProbeTarget(".htaccess",              Severity.MEDIUM,   "Apache access control file"),
    # 패키지 / 의존성 (정보 수집용)
    ProbeTarget("composer.json",          Severity.LOW,      "PHP Composer dependencies"),
    ProbeTarget("package.json",           Severity.LOW,      "Node.js package manifest"),
    # 로그 파일
    ProbeTarget("debug.log",              Severity.MEDIUM,   "Debug log file"),
    ProbeTarget("error.log",              Severity.MEDIUM,   "Error log file"),
    ProbeTarget("logs/error.log",         Severity.MEDIUM,   "Application error log"),
    # Windows IIS
    ProbeTarget("web.config",             Severity.HIGH,     "IIS web configuration (may contain connection strings)"),
]

# ---------------------------------------------------------------------------
# 민감 정보 탐지 패턴
# 파일을 가져왔을 때 실제 자격증명이 포함됐는지 2차 검증한다.
# ---------------------------------------------------------------------------
CREDENTIAL_PATTERNS: List[tuple[str, re.Pattern[str]]] = [
    ("DB password",       re.compile(r"(?i)(db_pass|database_password|DB_PASSWORD)\s*[=:]\s*\S+")),
    ("DB user",           re.compile(r"(?i)(db_user|database_user|DB_USER)\s*[=:]\s*\S+")),
    ("DB name",           re.compile(r"(?i)(db_name|database_name|DB_NAME)\s*[=:]\s*\S+")),
    ("Secret key",        re.compile(r"(?i)(secret_key|SECRET_KEY|APP_SECRET)\s*[=:]\s*['\"]?\S{8,}")),
    ("API key",           re.compile(r"(?i)(api_key|API_KEY|APIKEY)\s*[=:]\s*['\"]?\S{8,}")),
    ("Access token",      re.compile(r"(?i)(access_token|ACCESS_TOKEN)\s*[=:]\s*['\"]?\S{8,}")),
    ("AWS key",           re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Private key header",re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Git remote URL",    re.compile(r"url\s*=\s*https?://\S+")),
    ("MySQL DSN",         re.compile(r"mysql://\S+:\S+@\S+")),
    ("Postgres DSN",      re.compile(r"postgres(?:ql)?://\S+:\S+@\S+")),
    ("wp-config DB",      re.compile(r"define\(\s*['\"]DB_(PASSWORD|USER|NAME)['\"]")),
    ("Rails secret",      re.compile(r"secret_key_base:\s*\S{20,}")),
]

# 파일 가져왔을 때 "실제로 내용이 있는" 최소 바이트
MIN_CONTENT_BYTES = 20

# ---------------------------------------------------------------------------
# 정적 탐지: HTTP 상태 + 콘텐츠 타입으로 파일 노출 여부 1차 판단
# ---------------------------------------------------------------------------
_BLOCKED_CONTENT_TYPES = {
    "text/html", "application/xhtml+xml",
}


def _is_exposed(status_code: int, content_type: str, body: str) -> bool:
    """
    서버가 파일 내용을 실제로 반환했는지 판단한다.
    - 200이어도 HTML 오류 페이지를 내려보내는 경우를 걸러낸다.
    """
    if status_code != 200:
        return False
    if len(body) < MIN_CONTENT_BYTES:
        return False
    ct = content_type.split(";")[0].strip().lower()
    if ct in _BLOCKED_CONTENT_TYPES:
        # HTML 응답이지만 <html> 태그로 시작하면 오류 페이지로 간주
        stripped = body.lstrip()
        if stripped.lower().startswith("<!doctype") or stripped.lower().startswith("<html"):
            return False
    return True


def _extract_credential_evidence(body: str) -> Optional[str]:
    """본문에서 첫 번째 매칭되는 자격증명 패턴과 레이블을 반환한다."""
    for label, pattern in CREDENTIAL_PATTERNS:
        m = pattern.search(body)
        if m:
            # 매칭 값 일부만 반환 (최대 60자)
            snippet = m.group(0)[:60]
            return f"{label}: {snippet}"
    return None


# ---------------------------------------------------------------------------
# 메인 스캔 함수
# ---------------------------------------------------------------------------
def scan_sensitive_files(
    target_url: str,
    http_client: HttpClient,
    plugin_context: PluginContext,
) -> List[Finding]:
    """
    target_url의 웹 루트에서 민감 파일 노출 여부를 탐지한다.

    전략:
    1. PROBE_TARGETS 목록의 경로를 웹 루트 기준으로 절대 URL로 변환한다.
    2. GET 요청 후 HTTP 200 + 실제 파일 내용인지 확인한다.
    3. CREDENTIAL_PATTERNS로 2차 검증 — 실제 자격증명 포함 시 Confidence.CERTAIN,
       파일만 노출된 경우 Confidence.FIRM.
    4. 같은 경로 중복 Finding 없이 하나만 생성한다.
    """
    findings: List[Finding] = []

    # 웹 루트 추출 (쿼리/경로 제거)
    parsed = urlparse(target_url)
    web_root = f"{parsed.scheme}://{parsed.netloc}/"

    for target in PROBE_TARGETS:
        probe_url = urljoin(web_root, target.path)
        try:
            resp = http_client.get(probe_url)
            status = getattr(resp, "status_code", 0)
            body = getattr(resp, "text", "") or ""
            content_type = resp.headers.get("Content-Type", "") if hasattr(resp, "headers") else ""

            if not _is_exposed(status, content_type, body):
                continue

            # 2차 검증: 자격증명 패턴 포함 여부
            evidence = _extract_credential_evidence(body)
            if evidence:
                confidence = Confidence.CERTAIN
                severity = target.severity
                detail = f"응답 본문에서 자격증명 패턴이 발견되었습니다: {evidence}"
            else:
                confidence = Confidence.FIRM
                # 자격증명 미확인 파일은 한 단계 낮춤 (CRITICAL→HIGH, HIGH→MEDIUM)
                severity = _downgrade_severity(target.severity)
                detail = "파일이 인증 없이 노출되었습니다. 자격증명 패턴은 자동 탐지되지 않았으나 수동 확인이 필요합니다."

            logger.warning(
                "[sensitive_files] FOUND %s (status=%d confidence=%s)",
                probe_url, status, confidence.value,
            )

            findings.append(Finding(
                id=str(uuid.uuid4()),
                plugin="sensitive_files",
                severity=severity,
                confidence=confidence,
                title=f"ATT&CK T1552.001 — Exposed {target.description}",
                description=(
                    f"'{target.path}' 파일이 웹 루트에서 인증 없이 접근 가능합니다. "
                    f"{detail}"
                ),
                url=probe_url,
                method="GET",
                evidence=evidence or f"HTTP {status} — {len(body)} bytes returned",
                remediation=(
                    "1. 민감 파일을 웹 루트 밖으로 이동하거나 웹 서버에서 직접 접근을 차단하세요 (403). "
                    "2. .env, .git 등은 .htaccess/nginx location으로 명시 차단하세요. "
                    "3. 노출된 자격증명은 즉시 교체하세요."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1552/001/",
                    "ATT&CK:T1552.001",
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                    "https://cwe.mitre.org/data/definitions/312.html",
                ],
                cwe_id="CWE-312",
            ))

        except Exception as exc:
            logger.debug("[sensitive_files] request error (%s): %s", probe_url, exc)
            continue

    return findings


def _downgrade_severity(severity: Severity) -> Severity:
    """자격증명 미확인 시 심각도를 한 단계 낮춘다."""
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    idx = order.index(severity)
    return order[max(0, idx - 1)]
