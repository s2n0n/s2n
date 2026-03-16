# JWT 취약점 분석 플러그인 개발 계획서

> **작성일**: 2026-03-16
> **플러그인 ID**: P-07
> **플러그인 디렉터리**: `s2n/s2nscanner/plugins/jwt/`
> **목표 버전**: v1.2.0

---

## 1. 개요

### 1.1 배경 및 목적

JWT(JSON Web Token)는 현대 웹 서비스의 인증/인가 표준으로 자리잡았습니다. REST API, SPA, 마이크로서비스 환경에서 사실상 표준으로 사용되고 있으나, 잘못된 구현으로 인한 취약점이 실무에서 빈번하게 발견됩니다.

기존 s2n 플러그인(XSS, SQLi, CSRF 등)은 전통적인 웹 애플리케이션의 취약점을 대상으로 하며, JWT와 같은 **API 인증 레이어 취약점은 전혀 커버하지 않습니다**. `jwt` 플러그인은 이 공백을 채우는 것을 목적으로 합니다.

### 1.2 탐지 대상 취약점 개요

| ID | 취약점 | 심각도 | CWE |
|---|---|---|---|
| JWT-01 | Algorithm None 공격 | CRITICAL | CWE-347 |
| JWT-02 | 약한 HS256 시크릿 키 | HIGH | CWE-326 |
| JWT-03 | RS256 → HS256 다운그레이드 | CRITICAL | CWE-757 |
| JWT-04 | 만료(exp) 클레임 미검증 | HIGH | CWE-613 |
| JWT-05 | 페이로드 클레임 조작 (권한 상승) | HIGH | CWE-285 |
| JWT-06 | 민감 데이터 페이로드 노출 | MEDIUM | CWE-312 |
| JWT-07 | kid(Key ID) 헤더 인젝션 | CRITICAL | CWE-89 / CWE-22 |

### 1.3 s2n 아키텍처와의 연동 포인트

```
ScanConfig
  └── AuthConfig (auth_type=BEARER, token=<JWT>)
        ↓
  JWTPlugin.__init__(config: Optional[PluginConfig])
        ↓
  JWTPlugin.run(plugin_context: PluginContext)
        ├── jwt_extractor.py   → 요청/응답에서 JWT 자동 추출
        ├── jwt_analyzer.py    → 토큰 구조 분석 및 취약점 시나리오 실행
        └── jwt_reporter.py    → Finding 생성 및 PluginResult 반환
```

---

## 2. 취약점 상세 분석

### JWT-01 · Algorithm None 공격

**원리**

JWT 헤더의 `alg` 필드를 `"none"`, `"None"`, `"NONE"` 등으로 변조하고 서명을 제거한 토큰을 서버에 전송했을 때, 서버가 서명 검증을 건너뛰는 취약점입니다.

```
// 원본 토큰 헤더
{"alg": "HS256", "typ": "JWT"}

// 공격 토큰 헤더
{"alg": "none", "typ": "JWT"}
// 서명 부분을 빈 문자열로 대체: header.payload.
```

**탐지 방법**

1. 원본 토큰에서 헤더와 페이로드 추출
2. 헤더의 `alg`를 `none` / `None` / `NONE` / `nOnE`(케이스 우회 변형) 으로 변조
3. 서명 없이 재조합한 토큰(`header.payload.`)으로 보호된 엔드포인트에 요청
4. 200 OK 또는 인증 성공 응답을 받으면 취약점으로 판정

**판정 기준**

- ✅ 취약: 서명 없는 토큰으로 인증된 응답(`2xx`, 원본과 동일한 응답 바디) 수신
- ❌ 안전: 401 / 403 또는 서명 오류 메시지 응답

---

### JWT-02 · 약한 HS256 시크릿 키

**원리**

HMAC 기반 알고리즘(HS256/HS384/HS512)은 시크릿 키로 서명합니다. 키가 짧거나 예측 가능한 문자열(`secret`, `password`, `1234` 등)이면 오프라인 사전 공격으로 키를 복원할 수 있습니다.

**탐지 방법**

1. 토큰 알고리즘이 HS* 계열인지 확인
2. 내장 약한 키 사전(`weak_secrets.txt`) 대입하여 서명 검증 시도 (오프라인, 네트워크 요청 불필요)
3. 키 복원 성공 시 페이로드 조작 토큰을 생성하여 서버에 전송, 실제 인증 우회 확인

**약한 키 사전 구성 기준**

- 길이 16바이트 미만의 문자열
- 일반적인 기본값: `secret`, `jwt_secret`, `token`, `key`, `password`, `changeme` 등
- 숫자 패턴: `123456`, `000000` 등 (총 300개 내외)

---

### JWT-03 · RS256 → HS256 알고리즘 다운그레이드

**원리**

서버가 RS256(비대칭키)으로 서명된 토큰을 발급할 때, 공개키(Public Key)는 외부에 공개되어 있습니다. 공격자가 헤더의 `alg`를 `HS256`으로 변조하고, 서버의 **공개키를 HS256의 시크릿 키로 사용해** 토큰에 서명하면, 취약한 서버 구현이 이를 유효한 토큰으로 수락합니다.

**탐지 방법**

1. 원본 토큰 알고리즘이 RS256/RS384/RS512인지 확인
2. `/.well-known/jwks.json` 또는 표준 JWKS 엔드포인트에서 공개키 수집 시도
3. 공개키를 시크릿으로 사용해 HS256으로 재서명한 토큰 생성
4. 변조 토큰으로 보호된 엔드포인트에 요청 후 응답 검사

---

### JWT-04 · 만료(exp) 클레임 미검증

**원리**

`exp` 클레임에 과거 시각을 넣은 토큰을 서버가 수락하면, 토큰 만료를 검증하지 않는 것입니다.

**탐지 방법**

1. HS* 알고리즘이고 키가 이미 복원된 경우: `exp`를 과거 시각으로 변조한 토큰 재서명 후 전송
2. `alg:none` 공격이 성공한 경우: 서명 없이 `exp` 과거 변조 토큰 전송
3. 위 두 경우 모두 해당 없으면: 탐지 스킵(SKIPPED 처리)

---

### JWT-05 · 페이로드 클레임 조작 (권한 상승)

**원리**

JWT 페이로드에서 권한/역할 관련 클레임(`role`, `admin`, `is_admin`, `scope`, `permissions` 등)을 탐지하고, 값을 상승시킨 토큰으로 권한이 필요한 엔드포인트에 접근 시도합니다.

**탐지 방법**

1. 페이로드에서 권한 관련 클레임 키 탐지 (키워드 매칭)
2. 조작 가능한 경우(HS* 키 복원 또는 alg:none 성공)에만 실행
3. `role: "admin"`, `admin: true` 등으로 변조한 토큰으로 어드민 경로 접근 시도
4. 원본 요청 대비 응답 변화로 판정

---

### JWT-06 · 민감 데이터 페이로드 노출

**원리**

JWT 페이로드는 Base64URL로 인코딩되어 있을 뿐 **암호화가 아닙니다**. 클라이언트가 복호화 가능한 페이로드에 비밀번호, 이메일, 주민번호, 신용카드 번호 등 민감 정보가 포함되어 있으면 정보 노출 취약점입니다.

**탐지 방법**

1. JWT 페이로드를 Base64URL 디코딩
2. 민감 데이터 키워드 패턴 매칭: `password`, `passwd`, `secret`, `ssn`, `credit_card`, `cvv`, `pin` 등
3. 이메일 형식(`@` 포함), 전화번호 패턴, 14자리 숫자 패턴 등 정규식 탐지
4. 해당 클레임 키/값 쌍을 Finding의 `evidence`에 포함(값은 마스킹 처리)

---

### JWT-07 · kid(Key ID) 헤더 인젝션

**원리**

`kid` 헤더는 서명 검증에 사용할 키를 DB나 파일에서 조회하는 데 사용됩니다. `kid` 값이 쿼리에 직접 삽입되면 SQL Injection 또는 Path Traversal이 발생할 수 있습니다.

```json
// SQL Injection 예시
{"alg": "HS256", "kid": "' UNION SELECT 'attacker_secret' -- "}

// Path Traversal 예시
{"alg": "HS256", "kid": "../../dev/null"}
```

**탐지 방법**

1. 원본 토큰 헤더에 `kid` 클레임 존재 여부 확인
2. SQL Injection 페이로드를 `kid`에 삽입한 토큰 생성(서명은 페이로드 값과 일치하도록 구성)
3. Path Traversal 페이로드(`../../dev/null`, `../../etc/passwd`) 삽입
4. 서버 응답에서 SQL 오류 메시지 또는 예상치 못한 인증 성공 탐지

---

## 3. 기술 설계

### 3.1 파일 구조

```
s2n/s2nscanner/plugins/jwt/
├── __init__.py              # Plugin export: from .jwt_main import main as Plugin
├── jwt_main.py              # JWTPlugin 클래스 (BasePlugin 구현)
├── jwt_extractor.py         # 요청/응답/헤더/쿠키에서 JWT 자동 추출
├── jwt_analyzer.py          # 토큰 파싱, 변조 토큰 생성 로직
├── jwt_attacker.py          # 각 공격 시나리오 실행 (HTTP 요청 포함)
├── jwt_reporter.py          # Finding 생성 헬퍼
├── jwt_constants.py         # 상수 정의 (민감 키워드, alg none 변형 목록 등)
└── weak_secrets.txt         # 약한 HS256 시크릿 키 사전
```

### 3.2 클래스 설계

#### `JWTPlugin` (jwt_main.py)

```python
class JWTPlugin(BasePlugin):
    name = "jwt"
    description = "JWT 취약점 분석 플러그인 (alg:none, 약한 키, 다운그레이드 등)"

    def __init__(self, config: Optional[PluginConfig] = None) -> None: ...

    def run(self, plugin_context: PluginContext) -> PluginResult:
        # 1. JWT 추출
        # 2. 토큰 구조 분석
        # 3. 각 공격 시나리오 실행
        # 4. Finding 취합 및 PluginResult 반환
        ...
```

#### `JWTExtractor` (jwt_extractor.py)

```python
class JWTExtractor:
    """HTTP 요청/응답의 여러 위치에서 JWT를 추출합니다."""

    JWT_PATTERN = re.compile(
        r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
    )

    def extract_from_context(self, plugin_context: PluginContext) -> List[JWTToken]:
        """AuthConfig, 쿠키, 응답 헤더/바디에서 JWT를 탐색합니다."""
        ...

    def extract_from_response(self, response: HTTPResponse) -> List[JWTToken]:
        """응답 바디(JSON) 및 Set-Cookie 헤더에서 JWT 추출"""
        ...
```

#### `JWTAnalyzer` (jwt_analyzer.py)

```python
@dataclass
class JWTToken:
    raw: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: str
    algorithm: str
    source: str  # "auth_header" | "cookie" | "response_body" 등

class JWTAnalyzer:
    def parse(self, raw_token: str) -> JWTToken: ...
    def build_none_alg_token(self, token: JWTToken) -> List[str]: ...
    def build_hs256_downgrade_token(self, token: JWTToken, public_key: str) -> str: ...
    def crack_hs256_secret(self, token: JWTToken) -> Optional[str]: ...
    def build_tampered_payload(self, token: JWTToken, secret: str, changes: Dict) -> str: ...
    def find_sensitive_claims(self, token: JWTToken) -> List[str]: ...
```

#### `JWTAttacker` (jwt_attacker.py)

```python
class JWTAttacker:
    """각 JWT 공격 시나리오를 실제 HTTP 요청으로 실행합니다."""

    def __init__(self, http_client, target_urls: List[str], logger): ...

    def attack_none_alg(self, token: JWTToken) -> Optional[AttackResult]: ...
    def attack_weak_secret(self, token: JWTToken) -> Optional[AttackResult]: ...
    def attack_rs256_downgrade(self, token: JWTToken) -> Optional[AttackResult]: ...
    def attack_expired_token(self, token: JWTToken, secret: str) -> Optional[AttackResult]: ...
    def attack_privilege_escalation(self, token: JWTToken, secret: str) -> Optional[AttackResult]: ...
    def check_sensitive_exposure(self, token: JWTToken) -> Optional[AttackResult]: ...
    def attack_kid_injection(self, token: JWTToken) -> Optional[AttackResult]: ...
```

### 3.3 실행 흐름

```
JWTPlugin.run(plugin_context)
    │
    ├─ [Step 1] JWTExtractor.extract_from_context()
    │       └─ JWT가 없으면 → PluginStatus.SKIPPED 반환
    │
    ├─ [Step 2] JWTAnalyzer.parse(raw_token)
    │       └─ JWTToken 객체 생성
    │
    ├─ [Step 3] JWT-06: check_sensitive_exposure() — 항상 실행 (네트워크 요청 없음)
    │
    ├─ [Step 4] JWT-01: attack_none_alg()
    │       └─ alg none 4가지 변형 토큰으로 보호 엔드포인트 요청
    │
    ├─ [Step 5] 알고리즘 분기
    │   ├─ HS* 계열:
    │   │   ├─ JWT-02: crack_hs256_secret() [오프라인]
    │   │   │   └─ 성공 시 → JWT-04, JWT-05 실행 (키 사용)
    │   │   └─ JWT-07: attack_kid_injection() (kid 클레임 있는 경우)
    │   └─ RS* 계열:
    │       ├─ JWKS 엔드포인트 탐색
    │       └─ JWT-03: attack_rs256_downgrade() (공개키 획득 시)
    │
    └─ [Step 6] JWTReporter → Finding 목록 → PluginResult 반환
```

### 3.4 의존성

기존 s2n 의존성만 사용하는 것을 원칙으로 하되, JWT 서명 생성/검증에는 `PyJWT` 라이브러리를 추가합니다.

```
# requirements.txt에 추가
PyJWT>=2.8.0
cryptography>=41.0.0  # RS256 지원에 필요 (PyJWT 옵션 의존성)
```

기존 `requirements.txt`에 이미 `cryptography`가 포함되어 있을 경우 `PyJWT`만 추가합니다.

---

## 4. Finding 명세

각 취약점 탐지 시 생성되는 `Finding` 객체의 주요 필드를 정의합니다.

### JWT-01 Finding 예시

```python
Finding(
    id="jwt-001",
    plugin="jwt",
    severity=Severity.CRITICAL,
    title="JWT Algorithm None Attack Successful",
    description=(
        "서명이 없는 'alg: none' 토큰을 서버가 유효한 인증 토큰으로 수락했습니다. "
        "이는 서버가 JWT 서명을 전혀 검증하지 않음을 의미합니다."
    ),
    url="https://target.com/api/user/profile",
    parameter="Authorization",
    method="GET",
    payload='{"alg":"none","typ":"JWT"}.{"sub":"1234",...}.',
    evidence="HTTP 200 OK — 원본 응답과 동일한 바디 수신",
    remediation=(
        "JWT 라이브러리에서 허용 알고리즘을 명시적으로 지정하세요. "
        "예: jwt.decode(token, key, algorithms=['HS256']). "
        "'none' 알고리즘은 절대 허용 목록에 포함하지 마세요."
    ),
    cwe_id="CWE-347",
    cvss_score=9.8,
    confidence=Confidence.CERTAIN,
    references=[
        "https://portswigger.net/web-security/jwt",
        "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
    ]
)
```

---

## 5. 테스트 계획

### 5.1 단위 테스트

| 파일 | 테스트 대상 | 주요 케이스 |
|---|---|---|
| `test_jwt_extractor.py` | `JWTExtractor` | Authorization 헤더 추출, 쿠키 추출, 응답 바디 JSON 추출, JWT 없는 경우 빈 리스트 반환 |
| `test_jwt_analyzer.py` | `JWTAnalyzer` | 토큰 파싱 정확도, none alg 변형 토큰 생성, HS256 크래킹(weak_secrets.txt 포함), 민감 클레임 탐지 |
| `test_jwt_attacker.py` | `JWTAttacker` | Mock HTTP 응답 기반 공격 시나리오별 탐지/미탐지 판정 |
| `test_jwt_main.py` | `JWTPlugin` | JWT 없을 때 SKIPPED 반환, 전체 통합 흐름 |

### 5.2 테스트 픽스처 정의

```python
# test/unit/fixtures/jwt_fixtures.py

VALID_HS256_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
WEAK_SECRET_TOKEN = "eyJhbGciOiJIUzI1NiJ9..."  # secret='secret'으로 서명
NONE_ALG_TOKEN    = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0..."
RS256_TOKEN       = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
SENSITIVE_TOKEN   = "..."  # payload에 password 클레임 포함

# Mock 응답
AUTHENTICATED_RESPONSE   = MockHTTPResponse(status=200, body='{"user":"admin"}')
UNAUTHENTICATED_RESPONSE = MockHTTPResponse(status=401, body='{"error":"Unauthorized"}')
```

### 5.3 False Positive 시나리오

| 시나리오 | 기대 결과 |
|---|---|
| none alg 토큰 → 서버가 401 반환 | Finding 미생성 |
| HS256 크래킹 성공했지만 페이로드 조작 토큰 → 서버가 401 반환 | JWT-02 Finding은 생성, JWT-05 Finding 미생성 |
| 응답 바디에 `password` 키가 있지만 값이 해시값인 경우 | MEDIUM Finding 생성 (해시 여부 판단은 best-effort) |
| JWT가 없는 대상 | PluginStatus.SKIPPED, Finding 없음 |

---

## 6. 개발 일정

| 단계 | 내용 | 기간 |
|---|---|---|
| **Phase 0** | 사전 작업: `BasePlugin` 추상 클래스 정의(IFACE-05), `PyJWT` 의존성 추가 | 1일 |
| **Phase 1** | `jwt_extractor.py` 구현 및 단위 테스트 작성 | 2일 |
| **Phase 2** | `jwt_analyzer.py` 구현 (토큰 파싱, 변조 토큰 생성, HS256 크래킹) | 3일 |
| **Phase 3** | `jwt_attacker.py` 구현 (JWT-01~07 공격 시나리오 전체) | 4일 |
| **Phase 4** | `jwt_main.py`, `jwt_reporter.py`, `__init__.py` 통합 | 1일 |
| **Phase 5** | 전체 통합 테스트, False Positive 시나리오 검증, 문서 업데이트 | 2일 |
| **합계** | | **약 13일** |

---

## 7. 완료 기준 (Acceptance Criteria)

아래 모든 항목을 충족해야 개발 완료로 간주합니다.

- [ ] DVWA 없이 동작하는 단위 테스트 커버리지 80% 이상
- [ ] JWT-01 ~ JWT-07 모든 시나리오에 대해 True Positive 및 False Positive 테스트 케이스 존재
- [ ] JWT가 없는 대상 스캔 시 `PluginStatus.SKIPPED` 반환 (에러 아님)
- [ ] 모든 Finding에 `cwe_id`, `remediation`, `references` 포함
- [ ] `interfaces.ko.md` 문서에 jwt 플러그인 항목 추가
- [ ] `BasePlugin` Protocol을 상속하며 `run()` 인터페이스 준수
- [ ] 기존 플러그인 단위 테스트 통과 유지 (회귀 없음)
- [ ] `weak_secrets.txt`에 최소 200개 이상의 항목 포함

---

## 8. 리스크 및 대응 방안

| 리스크 | 가능성 | 대응 방안 |
|---|---|---|
| RS256 공개키 획득 실패 | 중간 | JWKS 탐색 실패 시 JWT-03 스킵 처리, Finding에 "공개키 미수집" 정보성 메시지 |
| HS256 크래킹이 너무 오래 걸림 | 높음 | 사전 크기를 300개 이하로 제한, 타임아웃 설정(기본 5초) |
| 보호된 엔드포인트 URL 특정 불가 | 중간 | ScanContext의 `discovered_urls`에서 인증 필요 응답(401/403)을 반환했던 URL 우선 사용 |
| PyJWT 버전 호환성 문제 | 낮음 | `>=2.8.0` 핀 고정, CI에서 버전 명시 |
