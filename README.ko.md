# S2N — 플러그인 기반 웹 취약점 스캐너

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

### CLI 사용

```bash
s2n scan \
  --url http://target.com \
  --plugin sql --plugin xss \
  --auth basic \
  --username admin \
  --password pass \
  --output results.json \
  --verbose
```

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

문서

- 데이터 타입 참고 문서: interfaces.en.md
- 소스 코드: interfaces.py

핵심 타입 및 데이터 모델

- s2n.s2nscanner.interfaces.ScanConfig
- s2n.s2nscanner.interfaces.PluginConfig
- s2n.s2nscanner.interfaces.ScannerConfig

결과 & 리포팅

- s2n.s2nscanner.interfaces.ScanReport
- s2n.s2nscanner.interfaces.Finding

열거형(Enums)

- s2n.s2nscanner.interfaces.Severity
- s2n.s2nscanner.interfaces.PluginStatus

기능

- 플러그인 아키텍처 기반의 모듈형 취약점 검사
- 요청/결과/출력에 대한 구조화된 데이터 모델
- 다양한 출력 형식 지원 (JSON, HTML, console)
- 스캐너 동작 및 플러그인 설정을 유연하게 구성 가능

---

라이선스

---

기여 가이드

프로젝트 코딩 스타일을 따르고, 새로운 기능을 추가할 경우 테스트 코드를 함께 작성해주세요.
인터페이스가 변경될 때는 `interfaces.en.md` 문서를 업데이트해야 합니다.
