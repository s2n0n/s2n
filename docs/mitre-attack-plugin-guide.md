# MITRE ATT&CK 기반 s2n 플러그인 통합 가이드

> ATT&CK DB 기반 플러그인을 추가할 때마다 참조하는 단일 마스터 문서.
> 개념 → 구현 → s2n 통합 → 검증 순으로 읽는다.

---

## 1. ATT&CK 핵심 개념 (최소 필수)

| 계층 | 설명 | 예시 |
|------|------|------|
| **Tactic** | 공격 목표 | `Initial Access`, `Execution`, `Lateral Movement` |
| **Technique** | 공격 방법 (TID) | `T1059` Command and Scripting Interpreter |
| **Sub-technique** | 세부 방법 | `T1059.001` PowerShell |

### STIX 데이터 — 사용 Object 타입

| Object | 용도 | 주요 필드 |
|--------|------|-----------|
| `attack-pattern` | Technique 정의 | `external_references[].external_id` (TID), `kill_chain_phases[].phase_name` (Tactic) |
| `relationship` | 객체 간 관계 | `relationship_type`: `uses` / `mitigates` / `detects` |
| `intrusion-set` | APT 그룹 | 확장 시 사용 |
| `malware` | 악성코드 | 확장 시 사용 |

### 데이터 소스

- **TAXII API (실시간)**: `https://attack-taxii.mitre.org/api/v21/`
  - Collection: `Enterprise ATT&CK` / `Mobile ATT&CK` / `ICS ATT&CK`
- **오프라인 STIX**: `https://github.com/mitre-attack/attack-stix-data`
  - 초기 개발 시 오프라인 JSON 캐시 권장 → 탐지 로직 안정화 후 TAXII 전환

---

## 2. 기존 플러그인 → ATT&CK 매핑 레지스트리

> 새 플러그인 추가 시 이 테이블을 먼저 업데이트한다.

| s2n Plugin | ATT&CK TID | Technique Name | Tactic |
|------------|------------|----------------|--------|
| `xss` | T1059.007 | JavaScript | Execution |
| `sqlinjection` | T1190 | Exploit Public-Facing Application | Initial Access |
| `oscommand` | T1059 | Command and Scripting Interpreter | Execution |
| `csrf` | T1185 | Browser Session Hijacking | Collection |
| `file_upload` | T1505.003 | Web Shell | Persistence |
| `brute_force` | T1110 | Brute Force | Credential Access |
| `soft_brute_force` | T1110 | Brute Force | Credential Access |
| `jwt` | T1528 | Steal Application Access Token | Credential Access |
| `autobot` | T1190 | Exploit Public-Facing Application | Initial Access |
| _(새 플러그인)_ | _TID_ | _Technique_ | _Tactic_ |

### ATT&CK Finding → TID 매핑 방법

| 방법 | 사용 시점 | 예시 |
|------|-----------|------|
| **룰 기반** | plugin_name으로 TID 직접 결정 | `plugin=="xss"` → `T1059.007` |
| **키워드 매칭** | Finding의 `description`/`evidence` 분석 | `"credential"` → Credential Access |
| **행동 패턴** | 다수 Finding 조합 분석 | lateral movement 탐지 시 |

---

## 3. s2n 플러그인 아키텍처 — 통합 흐름

새 ATT&CK 기반 플러그인을 추가할 때 반드시 거쳐야 하는 4개 통합 포인트:

```
[1] 플러그인 디렉토리 생성
        ↓
[2] discovery.py 자동 탐지 확인
        ↓
[3] runner.py CLI 기본 목록 등록  ← 빠뜨리기 쉬운 포인트
        ↓
[4] 위 §2 매핑 테이블 업데이트
```

### [1] 플러그인 디렉토리 구조

```
s2n/s2nscanner/plugins/<plugin_name>/
├── __init__.py           # Plugin export (필수)
├── <plugin_name>_main.py # 메인 클래스 + factory
├── <plugin_name>_scan.py # 스캔 로직 분리 (선택)
└── <plugin_name>_data.*  # 페이로드/룰셋 (선택)
```

### [2] `__init__.py` — 반드시 이 패턴

```python
from .<plugin_name>_main import main as Plugin
```

> `discovery.py`는 각 플러그인 패키지에서 `Plugin` 심볼을 찾아 자동 탐지한다.
> `excluded_modules = {"helper", "discovery", "registry"}` — 이 이름은 사용 금지.

### [3] 메인 클래스 — 인터페이스 계약

```python
from s2n.s2nscanner.interfaces import (
    Finding, Severity, Confidence,
    PluginConfig, PluginContext, PluginResult, PluginStatus, PluginError,
)
from s2n.s2nscanner.plugins.helper import resolve_client, resolve_depth, resolve_target_url
from s2n.s2nscanner.logger import get_logger

logger = get_logger("plugins.<plugin_name>")


class <PluginName>Plugin:
    name = "<plugin_name>"           # discover_plugins()가 반환하는 id
    description = "..."              # list-plugins / inspect-plugin 에 표시됨
    version = "0.1.0"

    def __init__(self, config: PluginConfig | None = None):
        self.config = config or {}

    def run(self, plugin_context: PluginContext) -> PluginResult:
        start_time = datetime.now()
        findings: list[Finding] = []
        try:
            http_client = resolve_client(plugin_context)
            target_urls = resolve_target_url(plugin_context)
            depth = resolve_depth(plugin_context)
            # ... 스캔 로직 ...
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.SUCCESS,
                findings=findings,
                start_time=start_time,
                end_time=datetime.now(),
                duration_seconds=(datetime.now() - start_time).total_seconds(),
            )
        except Exception as e:
            logger.exception("[%s] plugin error: %s", self.name, e)
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILED,
                findings=findings,
                start_time=start_time,
                end_time=datetime.now(),
                duration_seconds=(datetime.now() - start_time).total_seconds(),
                error=PluginError(error_type=type(e).__name__, message=str(e)),
            )


def main(config: PluginConfig | None = None):
    return <PluginName>Plugin(config)
```

### [4] CLI 기본 목록 등록 — `runner.py:153`

```python
# s2n/s2nscanner/cli/runner.py  (scan 함수 내부)
if run_all or not plugin_list:
    plugin_list = [
        "csrf", "sqlinjection", "file_upload", "oscommand",
        "xss", "brute_force", "soft_brute_force", "autobot", "jwt",
        "<새_플러그인_이름>",   # ← 여기에 추가
    ]
```

> **주의**: `discovery.py`가 자동 탐지하더라도, `runner.py`의 기본 목록에 없으면
> `s2n scan -u <url>` (플러그인 미지정 시)에 포함되지 않는다.
> `-p <plugin_name>` 으로 명시 호출은 가능하다.

---

## 4. ATT&CK Finding 데이터 모델

`Finding.references` 리스트에 ATT&CK 정보를 삽입하는 방식 권장
(현재 `interfaces.py`에 `metadata` 필드 없음):

```python
Finding(
    id=str(uuid.uuid4()),
    plugin=self.name,
    severity=Severity.MEDIUM,
    confidence=Confidence.FIRM,
    title="ATT&CK T1059.007 — JavaScript Execution (XSS)",
    description="Reflected XSS allows arbitrary JavaScript execution via user-supplied input.",
    url=target_url,
    evidence="<script>alert(1)</script>",
    remediation="Sanitize and encode all user input before rendering in HTML context.",
    references=[
        "https://attack.mitre.org/techniques/T1059/007/",  # ATT&CK URL
        "ATT&CK:T1059.007",                                 # 파싱용 태그
        "https://owasp.org/www-community/attacks/xss/",
    ],
    cwe_id="CWE-79",
)
```

> `interfaces.py`에 `attack_technique_id: Optional[str]` 필드 확장이 필요한 경우
> `interfaces.py`와 `finding.py` 모두 업데이트 후 기존 플러그인 호환성 확인.

---

## 5. 새 ATT&CK 플러그인 추가 체크리스트

```
[ ] §2 매핑 테이블에 새 플러그인 TID 등록
[ ] plugins/<name>/__init__.py — Plugin export
[ ] plugins/<name>/<name>_main.py — PluginConfig | None 생성자
[ ] plugins/<name>/<name>_main.py — run() → PluginResult
[ ] helper.py 공통 함수 사용 (scan_context 직접 접근 금지)
[ ] 에러: try/except → PluginResult(FAILED) + logger.exception
[ ] runner.py:153 기본 plugin_list에 추가
[ ] test/test_<name>.py 단위 테스트
[ ] discovery.py 자동 탐지 확인 (아래 검증 명령어 실행)
```

---

## 6. 강제 규칙 (NEVER / ALWAYS)

- **NEVER** `__init__`에 `PluginContext`를 파라미터로 받을 것
- **NEVER** `except: pass` 또는 `except Exception: pass`로 예외 묵살
- **NEVER** `scan_context.http_client`에 직접 접근 → `resolve_client()` 사용
- **ALWAYS** `__init__.py`에서 `Plugin` 심볼로 export
- **ALWAYS** 에러 시 `PluginResult(status=PluginStatus.FAILED, error=PluginError(...))` 반환
- **ALWAYS** `get_logger("plugins.<name>")` 사용
- **ALWAYS** `runner.py` 기본 목록 업데이트 (discovery만으로는 기본 실행 안 됨)

---

## 7. 검증 명령어

```bash
# [1] 플러그인 자동 탐지 확인
python -c "from s2n.s2nscanner.plugins.discovery import discover_plugins; \
  [print(p['id'], p['name']) for p in discover_plugins()]"

# [2] 특정 플러그인 상세 확인
s2n inspect-plugin <plugin_name>

# [3] 단위 테스트
python -m pytest test/test_<plugin_name>.py -v

# [4] 단독 실행 테스트
s2n scan -u http://target.example -p <plugin_name>

# [5] 전체 통합 실행 (기본 목록 포함 여부 확인)
s2n scan -u http://target.example --all
```
