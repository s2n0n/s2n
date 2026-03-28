"""JWT Finding 생성 헬퍼 - AttackResult를 Finding 객체로 변환합니다."""
import uuid
from typing import Any, Dict, List, Optional, Tuple

from s2n.s2nscanner.interfaces import Confidence, Finding, Severity
from s2n.s2nscanner.plugins.jwt.jwt_attacker import AttackResult
from s2n.s2nscanner.plugins.jwt.jwt_analyzer import JWTToken


# =============================================================================
# 취약점별 Finding 명세
# =============================================================================

_FINDING_SPECS: Dict[str, Dict[str, Any]] = {
    "JWT-01": {
        "severity": Severity.CRITICAL,
        "title": "JWT Algorithm None Attack Successful",
        "description": (
            "서명이 없는 'alg: none' 토큰을 서버가 유효한 인증 토큰으로 수락했습니다. "
            "이는 서버가 JWT 서명을 전혀 검증하지 않음을 의미하며, "
            "공격자는 임의의 페이로드를 담은 토큰으로 인증을 우회할 수 있습니다."
        ),
        "remediation": (
            "JWT 라이브러리에서 허용 알고리즘을 명시적으로 지정하세요. "
            "예: jwt.decode(token, key, algorithms=['HS256']). "
            "'none' 알고리즘은 절대 허용 목록에 포함하지 마세요. "
            "python-jose, PyJWT 등 주요 라이브러리는 기본적으로 none을 거부합니다."
        ),
        "cwe_id": "CWE-347",
        "cvss_score": 9.8,
        "references": [
            "https://portswigger.net/web-security/jwt",
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
            "https://cwe.mitre.org/data/definitions/347.html",
        ],
    },
    "JWT-02": {
        "severity": Severity.HIGH,
        "title": "JWT Weak HS256 Secret Key",
        "description": (
            "JWT 서명에 사용된 HMAC 시크릿 키가 사전 공격으로 복원되었습니다. "
            "이는 공격자가 임의의 페이로드로 유효한 JWT 토큰을 위조할 수 있음을 의미합니다."
        ),
        "remediation": (
            "최소 256비트(32바이트) 이상의 암호학적으로 안전한 무작위 시크릿 키를 사용하세요. "
            "Python: secrets.token_bytes(32) 또는 os.urandom(32). "
            "예측 가능한 문자열, 기본값('secret', 'password' 등), 짧은 패스워드는 절대 사용 금지."
        ),
        "cwe_id": "CWE-326",
        "cvss_score": 8.1,
        "references": [
            "https://portswigger.net/web-security/jwt",
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/326.html",
        ],
    },
    "JWT-03": {
        "severity": Severity.CRITICAL,
        "title": "JWT RS256 to HS256 Algorithm Confusion Attack",
        "description": (
            "서버가 RS256(비대칭키) JWT를 사용하지만, 서버의 RSA 공개키를 HMAC 시크릿으로 "
            "사용한 HS256 토큰을 유효한 것으로 수락했습니다. "
            "공개키는 공개되어 있으므로 누구나 이 방식으로 유효한 토큰을 위조할 수 있습니다."
        ),
        "remediation": (
            "JWT 검증 시 허용 알고리즘을 명시적으로 고정하세요. "
            "RS256 전용 서버: jwt.decode(token, public_key, algorithms=['RS256']). "
            "HS256을 허용 목록에 포함하지 마세요. "
            "알고리즘 혼용이 필요한 경우 별도의 키 쌍을 사용하세요."
        ),
        "cwe_id": "CWE-757",
        "cvss_score": 9.8,
        "references": [
            "https://portswigger.net/web-security/jwt/algorithm-confusion",
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
            "https://cwe.mitre.org/data/definitions/757.html",
        ],
    },
    "JWT-04": {
        "severity": Severity.HIGH,
        "title": "JWT Expiration (exp) Claim Not Validated",
        "description": (
            "만료된 JWT 토큰(exp 클레임이 과거 시각으로 설정)을 서버가 수락했습니다. "
            "이는 서버가 토큰 만료 시각을 검증하지 않음을 의미하며, "
            "탈취된 토큰이 영구적으로 유효하게 됩니다."
        ),
        "remediation": (
            "JWT 검증 라이브러리에서 exp 클레임 검증을 활성화하세요. "
            "PyJWT: jwt.decode(token, key, options={'verify_exp': True}) (기본값 True). "
            "만료된 토큰 수신 시 반드시 401 Unauthorized를 반환해야 합니다. "
            "적절한 토큰 만료 시간(access: 15분, refresh: 24시간)을 설정하세요."
        ),
        "cwe_id": "CWE-613",
        "cvss_score": 7.5,
        "references": [
            "https://portswigger.net/web-security/jwt",
            "https://tools.ietf.org/html/rfc7519#section-4.1.4",
            "https://cwe.mitre.org/data/definitions/613.html",
        ],
    },
    "JWT-05": {
        "severity": Severity.HIGH,
        "title": "JWT Privilege Escalation via Claim Manipulation",
        "description": (
            "JWT 페이로드의 권한 관련 클레임(role, admin 등)을 조작하여 권한 상승이 가능합니다. "
            "서버가 서명을 제대로 검증하지 않거나 약한 키를 사용하여 "
            "공격자가 관리자 권한을 획득할 수 있습니다."
        ),
        "remediation": (
            "JWT 서명을 반드시 검증 후 클레임을 사용하세요. "
            "권한 정보는 서버 측 DB/세션에서 조회하고, 토큰에 직접 저장하는 것을 지양하세요. "
            "강력한 서명 알고리즘(RS256)과 키 관리를 사용하고 토큰 만료를 짧게 설정하세요."
        ),
        "cwe_id": "CWE-285",
        "cvss_score": 8.8,
        "references": [
            "https://portswigger.net/web-security/jwt",
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://cwe.mitre.org/data/definitions/285.html",
        ],
    },
    "JWT-06": {
        "severity": Severity.MEDIUM,
        "title": "Sensitive Data Exposed in JWT Payload",
        "description": (
            "JWT 페이로드에 민감한 정보가 포함되어 있습니다. "
            "JWT는 Base64URL 인코딩되어 있을 뿐 암호화가 아니므로, "
            "토큰에 접근 가능한 누구나 페이로드를 디코딩하여 내용을 확인할 수 있습니다."
        ),
        "remediation": (
            "JWT 페이로드에 비밀번호, 개인정보(주민번호, 신용카드 등) 등 민감 데이터를 포함하지 마세요. "
            "꼭 포함이 필요하다면 JWE(JSON Web Encryption)를 사용하여 페이로드를 암호화하세요. "
            "최소한의 클레임(sub, exp, iat 등 표준 클레임)만 포함하세요."
        ),
        "cwe_id": "CWE-312",
        "cvss_score": 5.3,
        "references": [
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
            "https://tools.ietf.org/html/rfc7519",
            "https://cwe.mitre.org/data/definitions/312.html",
        ],
    },
    "JWT-07": {
        "severity": Severity.CRITICAL,
        "title": "JWT kid Header Injection (SQL/Path Traversal)",
        "description": (
            "JWT 헤더의 kid(Key ID) 파라미터가 입력 검증 없이 처리됩니다. "
            "SQL Injection 또는 Path Traversal 페이로드를 kid에 삽입하여 "
            "서명 검증 키를 공격자가 제어 가능한 값으로 대체할 수 있습니다."
        ),
        "remediation": (
            "kid 값을 데이터베이스 쿼리나 파일 경로에 직접 사용하지 마세요. "
            "허용된 kid 값의 화이트리스트를 유지하고 엄격하게 검증하세요. "
            "키를 메모리 내 맵(dict)에서 kid로 조회하는 방식을 권장합니다. "
            "파라미터화된 쿼리(Prepared Statement)를 사용하세요."
        ),
        "cwe_id": "CWE-89",
        "cvss_score": 9.8,
        "references": [
            "https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal",
            "https://owasp.org/www-project-web-security-testing-guide/",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    },
}


# =============================================================================
# Finding 생성 함수
# =============================================================================

def create_finding(
    attack_result: AttackResult,
    token: JWTToken,
    extra_description: str = "",
) -> Finding:
    """AttackResult로부터 Finding 객체를 생성합니다."""
    spec = _FINDING_SPECS.get(attack_result.attack_id, {})

    description = spec.get("description", "JWT 취약점이 탐지되었습니다.")
    if extra_description:
        description = f"{description}\n\n추가 정보: {extra_description}"

    return Finding(
        id=str(uuid.uuid4()),
        plugin="jwt",
        severity=spec.get("severity", Severity.MEDIUM),
        confidence=Confidence.CERTAIN if attack_result.success else Confidence.FIRM,
        title=spec.get("title", f"{attack_result.attack_id} 취약점"),
        description=description,
        url=attack_result.url if attack_result.url else None,
        parameter="Authorization",
        method=attack_result.method if attack_result.method != "OFFLINE" else None,
        payload=attack_result.token_used,
        evidence=attack_result.evidence,
        remediation=spec.get("remediation"),
        references=spec.get("references", []),
        cwe_id=spec.get("cwe_id"),
        cvss_score=spec.get("cvss_score"),
    )


def create_sensitive_finding(
    token: JWTToken,
    sensitive_claims: List[Tuple[str, str]],
    url: Optional[str] = None,
) -> Finding:
    """JWT-06 민감 데이터 노출 Finding을 생성합니다."""
    spec = _FINDING_SPECS["JWT-06"]
    claims_str = ", ".join(f"{k}={v}" for k, v in sensitive_claims)
    description = (
        f"{spec['description']}\n\n"
        f"탐지된 민감 클레임: [{claims_str}]"
    )

    return Finding(
        id=str(uuid.uuid4()),
        plugin="jwt",
        severity=spec["severity"],
        confidence=Confidence.FIRM,
        title=spec["title"],
        description=description,
        url=url,
        parameter="JWT Payload",
        method=None,
        payload=None,
        evidence=f"민감 클레임 탐지: {claims_str}",
        remediation=spec["remediation"],
        references=spec["references"],
        cwe_id=spec["cwe_id"],
        cvss_score=spec["cvss_score"],
    )
