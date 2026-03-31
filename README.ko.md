# S2N — 플러그인 기반 웹 취약점 스캐너

[![PyPI Version](https://img.shields.io/pypi/v/s2n)](https://pypi.org/project/s2n/)
[![PyPI downloads](https://img.shields.io/pypi/dm/s2n)](https://pypi.org/project/s2n/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<pre>
 (`-').->        <-. (`-')_
 ( OO)_             \( OO) )
(_)--\_)  .----. ,--./ ,--/
/    _ / \_,-.  ||   \ |  |
\_..`--.    .' .'|  . '|  |)
.-._)   \ .'  /_ |  |\    |
\       /|      ||  | \   |
 `-----' `------'`--'  `--'
</pre>

> 가벼우면서 플러그인 기반으로 동작하는 웹 취약점 스캐너 라이브러리입니다.  
> 핵심 데이터 타입과 인터페이스는 `s2n.s2nscanner.interfaces`에 정의되어 있습니다.  
> 더 자세한 타입 문서는 [`interfaces.en.md`](/docs/interfaces.en.md)에서 확인할 수 있습니다.

---

## 빠른 설치

### CLI 사용 방법

터미널에서 스캔을 실행하는 예시입니다:

```bash
s2n scan \
  --url http://target.com \
  --all \
  --auth auto \
  --username admin \
  --password pass \
  --output-format html \
  --output results.html
```

주요 옵션 목록:

- `-u, --url`: 스캔 대상 URL (필수)
- `-p, --plugin`: 특정 플러그인 선택 (여러 번 사용 가능)
- `--all`: 모든 기본 플러그인 실행
- `-a, --auth`: 인증 타입 선택 (NONE, BASIC, BEARER, AUTO 등)
- `--login-url`: 자동 인증을 위한 로그인 페이지 URL
- `-o, --output`: 결과를 파일로 저장
- `--output-format`: 출력 형식 선택 (JSON, HTML, CSV, CONSOLE, MULTI)
- `--crawler-depth`: 크롤링 탐색 깊이 설정 (기본값: 2)
- `-v, --verbose`: 상세 로그 출력 활성화

### Chrome 확장 프로그램 사용 (GUI)

S2N은 CLI뿐만 아니라 Chrome 확장 프로그램을 통한 편리한 스캔 기능을 제공합니다. 확장 프로그램을 로컬 S2N 호스트와 연동하려면 다음 단계를 따르세요.

1. **확장 프로그램 설치**: 크롬 웹 스토어나 개발자 모드(Developer Mode)를 통해 S2N 스캐너 확장 프로그램을 설치합니다.
2. **호스트 연동**: 터미널에서 아래 명령어를 실행하여 크롬 브라우저와 통신할 수 있는 Native Messaging Host를 설치합니다. (기본 설정된 공식 Extension ID로 자동 연동됩니다)
   ```bash
   s2n install-gui
   ```
3. 브라우저를 재시작하고 확장 프로그램 아이콘을 클릭하여 스캐너를 시작하세요.

Python 사용 예시

```python
from s2n import Scanner, ScanConfig, PluginConfig, AuthConfig
from s2n.interfaces import Severity, AuthType

# ScanConfig 생성
config = ScanConfig(
    target_url="http://target.com",
    scanner_config=ScannerConfig(crawl_depth=3),
    plugin_configs={
        "sql": PluginConfig(
            enabled=True,
            max_payloads=50
        )
    },
    auth_config=AuthConfig(
        auth_type=AuthType.BASIC,
        username="admin",
        password="pass"
    )
)

# ScanConfig로 스캔 실행
scanner = Scanner(config)
report = scanner.scan()

# 결과 처리
print(f"[RESULT]: {report.summary.total_vulnerabilities}개")
for result in report.plugin_results:
    for finding in result.findings:
        if finding.severity in [Severity.CRITICAL, SeverityHIGH]:
            print(f"[{finding.severity}] {finding.title}")
```

---

## 주요 타입 참고

### 문서

- 데이터 타입 참고 문서: interfaces.en.md
- 소스 코드: interfaces.py

### 핵심 타입 및 데이터 모델

- s2n.s2nscanner.interfaces.ScanConfig
- s2n.s2nscanner.interfaces.PluginConfig
- s2n.s2nscanner.interfaces.ScannerConfig

### 결과 & 리포팅

- s2n.s2nscanner.interfaces.ScanReport
- s2n.s2nscanner.interfaces.Finding

### 열거형(Enums)

- s2n.s2nscanner.interfaces.Severity
- s2n.s2nscanner.interfaces.PluginStatus

기능

- 플러그인 기반 아키텍처: 모듈형 취약점 검사를 통한 손쉬운 확장성 제공
- 고급 크롤링 및 탐지: 범용 로그인 지원 및 공격 포인트 자동 탐지 기능
- 지원 플러그인: SQL Injection, XSS, CSRF, JWT, OS Command Injection, File Upload, Brute Force 등
- 다양한 클라이언트: 강력한 CLI와 Chrome Extension GUI를 통한 편의성 제공
- 풍부한 리포팅: JSON, HTML, CSV, Console 등 다양한 출력 형식 지원
- 크로스 플랫폼 지원: Windows, Linux, macOS 환경을 위한 최적화된 탐지 패턴
- 자동화 테스트: 보안 회귀 테스트를 위한 CI/CD 연동 지원

---

라이선스

---

기여 가이드

프로젝트 코딩 스타일을 따르고, 새로운 기능을 추가할 경우 테스트 코드를 함께 작성해주세요.
인터페이스가 변경될 때는 `interfaces.en.md` 문서를 업데이트해야 합니다.
