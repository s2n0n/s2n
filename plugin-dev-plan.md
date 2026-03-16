# S2N 스캐너 플러그인 개발 계획서

> **작성일**: 2026-03-16
> **대상 버전**: v1.1.0 이후
> **목적**: s2n 플러그인 아키텍처를 활용한 신규 기능 확장 로드맵

---

## 1. 현황 요약

현재 s2n은 아래 7개의 플러그인을 보유하고 있습니다.

| 플러그인 | 탐지 대상 | 상태 |
|---|---|---|
| `sqlinjection` | SQL Injection (Error-Based, Time-Based) | 운영 중 |
| `xss` | Reflected XSS (Stored XSS는 데드코드) | 운영 중 |
| `csrf` | CSRF 토큰 부재 | 운영 중 |
| `brute_force` | 로그인 Brute Force (Selenium) | 운영 중 |
| `soft_brute_force` | Rate Limiting 부재 탐지 | 운영 중 |
| `file_upload` | 악성 파일 업로드 | 운영 중 |
| `oscommand` | OS Command Injection | 운영 중 |

기존 플러그인에 알려진 품질 이슈(False Positive, 데드코드, 인터페이스 불일치 등)가 존재하며, 새 플러그인 추가 전 `BasePlugin` 추상 클래스 정의 등 인터페이스 정비가 선행되어야 합니다.

---

## 2. 신규 플러그인 후보 목록

아래는 s2n에 추가를 검토할 수 있는 플러그인 후보 전체 목록입니다.

| # | 플러그인 이름 | 탐지 대상 | 난이도 | 비고 |
|---|---|---|---|---|
| P-01 | `ssrf` | Server-Side Request Forgery | ★★★ | OWASP Top 10 |
| P-02 | `xxe` | XML External Entity Injection | ★★★ | OWASP Top 10 |
| P-03 | `open_redirect` | Open Redirect | ★★ | — |
| P-04 | `path_traversal` | Directory/Path Traversal | ★★ | — |
| P-05 | `security_headers` | 보안 헤더 미설정 탐지 | ★ | 구현 난이도 낮음 |
| P-06 | `cors` | CORS Misconfiguration | ★★ | — |
| P-07 | `jwt` | JWT 취약점 (alg:none, 약한 시크릿 등) | ★★★ | API 보안 |
| P-08 | `idor` | Insecure Direct Object Reference | ★★★★ | 컨텍스트 의존성 높음 |
| P-09 | `subdomain_takeover` | 서브도메인 탈취 가능 여부 | ★★★ | DNS 기반 |
| P-10 | `graphql` | GraphQL 인트로스펙션/인젝션 | ★★★ | 최신 API 대상 |
| P-11 | `ssti` | Server-Side Template Injection | ★★★ | 고위험 |
| P-12 | `report_exporter` | PDF/Markdown 리포트 내보내기 | ★★ | 리포팅 고도화 |
| P-13 | `async_engine` | 비동기 스캔 엔진 | ★★★★ | 성능 개선 |
| P-14 | `plugin_test_framework` | 플러그인 단위 테스트 자동화 | ★★★ | 품질 인프라 |

---

## 3. 개발 대상 선정

후보 목록 중 **기술적 완성도, 취약점 중요도, 구현 현실성**을 종합적으로 고려하여 아래 4개를 우선 개발 대상으로 선정합니다.

---

### ✅ P-01 · SSRF (Server-Side Request Forgery) 플러그인

**선정 이유**
OWASP Top 10 2021에 새롭게 진입한 항목으로, 클라우드 환경(AWS/GCP 메타데이터 엔드포인트 등)에서의 공격 영향이 매우 크지만 기존 스캐너에서 커버리지가 낮은 영역입니다. URL 파라미터를 대상으로 외부 콜백 서버(OOB)로의 요청 유도 여부를 탐지하는 방식으로 구현하며, 기존 HTTP 클라이언트 및 크롤러 구조를 그대로 활용할 수 있어 s2n 아키텍처와의 호환성이 좋습니다.

**주요 구현 내용**

- URL 파라미터 및 헤더(Referer, Host 등)에 외부 URL 페이로드 삽입
- OOB(Out-of-Band) 콜백 서버 연동 또는 DNS 응답 기반 탐지
- 클라우드 메타데이터 주소(`169.254.169.254` 등) 접근 시도 탐지
- 내부망 IP 대역(RFC 1918) 응답 여부 확인

**산출물**

```
s2n/s2nscanner/plugins/ssrf/
├── __init__.py
├── ssrf_main.py
├── ssrf_payloads.json
└── ssrf_utils.py
```

**우선순위**: 🔴 High

---

### ✅ P-06 · CORS Misconfiguration 플러그인

**선정 이유**
SPA(React, Vue 등) 기반 프론트엔드가 보편화되면서 CORS 설정 오류는 실무에서 가장 자주 발견되는 취약점 중 하나입니다. `Origin` 헤더 조작에 대한 서버의 응답(`Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`)을 검사하는 방식으로, 구현 복잡도 대비 실질적 탐지 가치가 높습니다. 기존 HTTP 클라이언트로 구현 가능하여 Selenium 의존성이 없습니다.

**주요 구현 내용**

- Reflected Origin: `Origin: attacker.com` 전송 후 응답 헤더 검사
- Null Origin: `Origin: null` 허용 여부 확인
- Wildcard + Credentials 조합 탐지 (`*` + `credentials: true` 동시 허용)
- 서브도메인 와일드카드 우회 패턴 탐지 (`evil.target.com`)

**산출물**

```
s2n/s2nscanner/plugins/cors/
├── __init__.py
├── cors_main.py
└── cors_utils.py
```

**우선순위**: 🔴 High

---

### ✅ P-07 · JWT 취약점 분석 플러그인

**선정 이유**
REST API 기반 서비스의 인증 수단으로 JWT가 표준처럼 사용되고 있으나, `alg:none` 공격, 약한 HS256 시크릿, 서명 키 혼용(`RS256 → HS256` 다운그레이드) 등 JWT 고유의 취약점은 기존 웹 스캐너 플러그인으로는 탐지가 어렵습니다. API 보안에 특화된 플러그인으로서 차별점이 명확하며, s2n의 `AuthConfig`(Bearer 토큰) 구조와 자연스럽게 연동됩니다.

**주요 구현 내용**

- 요청/응답에서 JWT 자동 추출 (헤더, 쿠키, 바디)
- `alg: none` 조작 후 서버 응답 검증
- HS256 약한 시크릿 사전 대입 (오프라인)
- `RS256 → HS256` 알고리즘 다운그레이드 시도
- JWT 페이로드 클레임 조작(sub, role, exp 변경) 후 인가 우회 시도
- 만료된 토큰 재사용 허용 여부 확인

**산출물**

```
s2n/s2nscanner/plugins/jwt/
├── __init__.py
├── jwt_main.py
├── jwt_analyzer.py
├── jwt_payloads.json
└── weak_secrets.txt
```

**우선순위**: 🟠 Medium-High

---

### ✅ P-14 · 플러그인 테스트 자동화 프레임워크

**선정 이유**
현재 s2n 테스트 코드는 플러그인마다 구조와 수준이 다르며, Mock 헬퍼(`mock_helper.py`)가 있음에도 활용이 일관되지 않습니다. 새로운 플러그인을 안정적으로 추가하고 기존 플러그인의 False Positive/Negative를 검증하려면, **취약한 서버 응답 픽스처 기반의 표준 테스트 구조**가 필요합니다. 기능 플러그인은 아니지만, 프로젝트 전체의 품질 기반이 되는 인프라 작업입니다.

**주요 구현 내용**

- `BasePluginTest` 추상 테스트 클래스 정의 (모든 플러그인 테스트가 상속)
- DVWA 없이 동작하는 `VulnerableResponseFixture`: 취약/정상 응답 Mock 셋 표준화
- `PluginTestRunner`: 플러그인명만 지정하면 통합 테스트 자동 실행
- False Positive / False Negative 시나리오 분리 검증
- 기존 테스트(`test_xss_unit.py`, `test_sqli_plugin.py` 등) 마이그레이션

**산출물**

```
test/
├── framework/
│   ├── __init__.py
│   ├── base_plugin_test.py
│   ├── fixtures/
│   │   ├── vulnerable_responses.py
│   │   └── safe_responses.py
│   └── plugin_test_runner.py
└── unit/ (기존 테스트 마이그레이션)
```

**우선순위**: 🟠 Medium-High

---

## 4. 개발 일정 (안)

```
Phase 1 — 기반 정비 (Before v1.1.0)
  ├── BasePlugin 추상 클래스 정의 (IFACE-05)
  ├── 플러그인 config 타입 통일 (IFACE-01)
  └── 테스트 프레임워크 구축 (P-14)

Phase 2 — 신규 플러그인 개발 (v1.1.0)
  ├── CORS Misconfiguration 플러그인 (P-06)
  └── SSRF 플러그인 (P-01)

Phase 3 — 고도화 (v1.2.0)
  └── JWT 취약점 분석 플러그인 (P-07)
```

---

## 5. 공통 개발 가이드라인

모든 신규 플러그인은 아래 기준을 준수합니다.

- **인터페이스**: `BasePlugin` Protocol 상속 및 `run(plugin_context: PluginContext) -> PluginResult` 구현
- **타입 통일**: config 파라미터는 `Optional[PluginConfig]`으로 고정
- **안전성**: 스캔 중 서버에 생성된 임시 리소스(업로드 파일, DB 레코드 등)는 반드시 정리 로직 포함
- **테스트**: `BasePluginTest`를 상속한 단위 테스트 및 False Positive 시나리오 필수 작성
- **문서화**: `interfaces.ko.md` Finding 필드 중 `cwe_id`, `remediation`, `references` 반드시 포함
