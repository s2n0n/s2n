"""JWT 취약점 분석 플러그인 - JWT-01 ~ JWT-07 시나리오를 실행합니다."""
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from s2n.s2nscanner.interfaces import (
    Finding,
    PluginContext,
    PluginError,
    PluginResult,
    PluginStatus,
)
from s2n.s2nscanner.logger import get_logger
from s2n.s2nscanner.plugins.helper import resolve_client, resolve_target_url
from s2n.s2nscanner.plugins.jwt.jwt_attacker import AttackResult, JWTAttacker
from s2n.s2nscanner.plugins.jwt.jwt_analyzer import JWTAnalyzer
from s2n.s2nscanner.plugins.jwt.jwt_constants import RS_ALGORITHMS
from s2n.s2nscanner.plugins.jwt.jwt_extractor import JWTExtractor
from s2n.s2nscanner.plugins.jwt.jwt_reporter import create_finding, create_sensitive_finding

logger = get_logger("plugins.jwt")

_WEAK_SECRETS_FILE = Path(__file__).parent / "weak_secrets.txt"


def _load_weak_secrets() -> List[str]:
    """weak_secrets.txt에서 시크릿 사전을 로드합니다."""
    if not _WEAK_SECRETS_FILE.exists():
        return []
    with _WEAK_SECRETS_FILE.open("r", encoding="utf-8") as fp:
        return [
            line.strip()
            for line in fp
            if line.strip() and not line.startswith("#")
        ]


# 모듈 로드 시 1회만 로딩
WEAK_SECRETS: List[str] = _load_weak_secrets()


class JWTPlugin:
    name = "jwt"
    description = "JWT 취약점 분석 플러그인 (alg:none, 약한 키, 알고리즘 다운그레이드, 클레임 조작 등)"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.timeout = int(self.config.get("timeout", 5))
        self.http = None  # resolve_client 폴백용

    def run(self, plugin_context: PluginContext) -> PluginResult:  # noqa: C901
        start_dt = datetime.now()
        findings: List[Finding] = []
        requests_sent = 0
        log = plugin_context.logger or logger

        try:
            client = resolve_client(self, plugin_context)
            target_url = resolve_target_url(self, plugin_context)
            target_urls: List[str] = getattr(plugin_context, "target_urls", None) or [target_url]

            # ── Step 1: JWT 토큰 추출 ────────────────────────────────────────
            extractor = JWTExtractor()
            raw_tokens = extractor.extract_from_context(plugin_context)

            if not raw_tokens:
                log.info("[JWTPlugin] JWT 토큰을 찾을 수 없습니다. SKIPPED 반환.")
                return PluginResult(
                    plugin_name=self.name,
                    status=PluginStatus.SKIPPED,
                    duration_seconds=(datetime.now() - start_dt).total_seconds(),
                )

            log.info(f"[JWTPlugin] {len(raw_tokens)}개의 JWT 토큰 발견")

            analyzer = JWTAnalyzer()
            attacker = JWTAttacker(client, target_urls, log)

            for raw_token in raw_tokens:
                token = analyzer.parse(raw_token, source="context")
                if token is None:
                    log.debug(f"[JWTPlugin] 토큰 파싱 실패: {raw_token[:40]}...")
                    continue

                log.info(f"[JWTPlugin] 토큰 분석 시작 — alg={token.algorithm}")

                # ── Step 2: JWT-06 민감 데이터 노출 (정적, 네트워크 요청 없음) ──
                sensitive_claims = analyzer.find_sensitive_claims(token)
                if sensitive_claims:
                    log.info(f"[JWTPlugin] JWT-06: 민감 클레임 {len(sensitive_claims)}개 탐지")
                    findings.append(
                        create_sensitive_finding(token, sensitive_claims, target_url)
                    )

                # ── Step 3: JWT-01 Algorithm None 공격 ───────────────────────
                log.info("[JWTPlugin] JWT-01: Algorithm None 공격 시작")
                none_results = attacker.attack_none_alg(token)
                requests_sent += 7  # 베이스라인 1 + none 변형 6
                none_alg_success = bool(none_results)
                for result in none_results:
                    findings.append(create_finding(result, token))

                # ── Step 4: 알고리즘별 분기 ──────────────────────────────────
                cracked_secret: Optional[str] = None

                if token.algorithm.upper() in ("HS256", "HS384", "HS512"):
                    # JWT-02: 약한 시크릿 크래킹 (오프라인)
                    log.info("[JWTPlugin] JWT-02: HS256 시크릿 크래킹 시작")
                    cracked_secret = attacker.attack_weak_secret(token, WEAK_SECRETS)
                    if cracked_secret:
                        log.info(
                            f"[JWTPlugin] JWT-02: 시크릿 키 복원 성공 → '{cracked_secret}'"
                        )
                        weak_result = AttackResult(
                            attack_id="JWT-02",
                            success=True,
                            token_used=f"(오프라인 크래킹) 복원된 키: '{cracked_secret}'",
                            url=target_url,
                            method="OFFLINE",
                            status_code=0,
                            response_body="",
                            evidence=(
                                f"HMAC-{token.algorithm[-3:]} 서명 대조로 시크릿 키 "
                                f"'{cracked_secret}' 복원 성공 (오프라인 사전 공격)"
                            ),
                        )
                        findings.append(create_finding(weak_result, token))

                    # JWT-07: kid 헤더 인젝션 (kid 클레임이 있는 경우만)
                    if "kid" in token.header:
                        log.info("[JWTPlugin] JWT-07: kid 헤더 인젝션 공격 시작")
                        kid_results = attacker.attack_kid_injection(token)
                        requests_sent += len(kid_results) + 1
                        for result in kid_results:
                            findings.append(create_finding(result, token))

                elif token.algorithm.upper() in RS_ALGORITHMS:
                    # JWT-03: RS256 → HS256 알고리즘 다운그레이드
                    log.info("[JWTPlugin] JWT-03: RS256→HS256 다운그레이드 공격 시작")
                    public_key_pem = attacker.fetch_jwks(target_url)
                    requests_sent += 12  # JWKS 엔드포인트 수 (대략)
                    if public_key_pem:
                        downgrade_results = attacker.attack_rs256_downgrade(
                            token, public_key_pem
                        )
                        requests_sent += 2  # 베이스라인 + 공격
                        for result in downgrade_results:
                            findings.append(create_finding(result, token))
                    else:
                        log.info("[JWTPlugin] JWT-03: 공개키 수집 실패 — 스킵")

                # ── Step 5: JWT-04 만료 미검증 (키 복원 또는 alg:none 성공 시만) ──
                if cracked_secret or none_alg_success:
                    log.info("[JWTPlugin] JWT-04: 만료 클레임 미검증 공격 시작")
                    expired_results = attacker.attack_expired_token(
                        token,
                        secret=cracked_secret,
                        use_none_alg=(none_alg_success and cracked_secret is None),
                    )
                    requests_sent += 1
                    for result in expired_results:
                        findings.append(create_finding(result, token))

                # ── Step 6: JWT-05 권한 상승 (키 복원 또는 alg:none 성공 시만) ──
                if cracked_secret or none_alg_success:
                    log.info("[JWTPlugin] JWT-05: 권한 상승 공격 시작")
                    priv_results = attacker.attack_privilege_escalation(
                        token,
                        secret=cracked_secret,
                        use_none_alg=(none_alg_success and cracked_secret is None),
                    )
                    requests_sent += 1
                    for result in priv_results:
                        findings.append(create_finding(result, token))

        except Exception as exc:
            log.exception(f"[JWTPlugin.run] 플러그인 오류: {exc}")
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILED,
                error=PluginError(
                    error_type=type(exc).__name__,
                    message=str(exc),
                    traceback=str(exc.__traceback__),
                ),
                duration_seconds=(datetime.now() - start_dt).total_seconds(),
            )

        status = PluginStatus.PARTIAL if findings else PluginStatus.SUCCESS
        return PluginResult(
            plugin_name=self.name,
            status=status,
            findings=findings,
            duration_seconds=(datetime.now() - start_dt).total_seconds(),
            requests_sent=requests_sent,
        )


def main(config: Optional[Dict[str, Any]] = None) -> JWTPlugin:
    return JWTPlugin(config)
