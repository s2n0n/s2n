---
description: s2n 프로젝트 코드 리뷰 절차
---

# s2n 코드 리뷰 워크플로우

## 대상 범위

- `s2n/s2nscanner/` 하위 모든 Python 파일
- `test/` 하위 테스트 파일
- `pyproject.toml`, `requirements*.txt` 의존성 변경

---

## 1단계: 변경 범위 파악

변경된 파일 목록과 diff를 확인한다.

```
git diff --stat HEAD~1
git diff HEAD~1 -- s2n/ test/
```

리뷰 전에 다음 사항을 명확히 한다.
- 어떤 플러그인 또는 모듈이 변경되었는가
- `interfaces.py`의 공개 타입(dataclass, Enum)이 수정되었는가
- 신규 플러그인인가, 기존 플러그인 수정인가

---

## 2단계: 정적 분석 실행

// turbo
```
cd /Users/tekwoo/Desktop/work/code-projects/s2n && python -m py_compile $(git diff --name-only HEAD~1 | grep '\.py$' | tr '\n' ' ') && echo "syntax OK"
```

문법 오류가 없는지 먼저 확인한다. 오류가 있으면 리뷰를 중단하고 수정을 요청한다.

---

## 3단계: 테스트 실행

// turbo
```
cd /Users/tekwoo/Desktop/work/code-projects/s2n && python -m pytest test/ -v --tb=short 2>&1 | tail -40
```

- 전체 테스트가 통과해야 리뷰를 계속 진행한다.
- 실패한 테스트가 있으면 해당 테스트 파일과 변경 코드를 함께 검토한다.

---

## 4단계: 인터페이스 계약 검토

`interfaces.py`에 정의된 타입과의 일관성을 확인한다.

### 확인 항목

**Finding 생성 시 필수 필드**
- `id`: `str(uuid.uuid4())` 로 생성
- `plugin`: 플러그인 이름 문자열 (소문자, 언더스코어 구분)
- `severity`: `Severity` Enum 값만 사용
- `confidence`: `Confidence` Enum 값만 사용
- `title`, `description`: 비어있지 않을 것

**PluginContext 사용 패턴**
- `plugin_context.scan_context.config` 를 통해 설정 접근
- `plugin_context.logger` 가 `None` 일 수 있으므로 fallback 처리 필요
  ```python
  # 올바른 패턴
  context_logger = getattr(plugin_context, "logger", None) or logger
  ```

**frozen dataclass 주의**
- `ScanRequest`, `ScanConfig`, `PluginConfig` 등은 `frozen=True`
- 인스턴스 생성 후 필드를 직접 수정하면 안 된다

---

## 5단계: 플러그인 코드 패턴 검토

### 5-1. 함수 시그니처

플러그인 진입 함수는 아래 형태를 따른다.

```python
def <plugin_name>_scan(
    target_url: str,
    http_client: Optional[HttpClient] = None,
    plugin_context: Optional[PluginContext] = None,
) -> List[Finding]:
```

- 반환 타입은 항상 `List[Finding]`
- 오류 발생 시 예외를 올리지 않고 빈 리스트 또는 부분 결과를 반환

### 5-2. 에러 처리

```python
# 올바른 패턴: 모듈 레벨 로거를 fallback으로 사용
logger = get_logger("plugins.<name>")

def scan(...):
    context_logger = getattr(plugin_context, "logger", None) or logger
    try:
        ...
    except Exception as e:
        context_logger.error(f"[<plugin>_scan] Error scanning {target_url}: {e}")
        return results
```

- `except Exception` 은 최외곽 한 군데만 허용
- 에러 메시지에 `target_url` 포함
- 내부 서브함수에서는 예외를 잡지 않고 상위로 전파

### 5-3. Finding 생성

- `severity=Severity.INFO`는 취약점이 없는 정상 케이스에 사용
- 취약점 발견 시 `Severity.HIGH` 또는 `Severity.MEDIUM` 사용
- `confidence`는 자동 탐지 결과에 `Confidence.FIRM`, 추정에 `Confidence.TENTATIVE`
- `remediation`은 취약점 Finding에만 작성, INFO Finding은 `None`

### 5-4. HTTP 클라이언트 사용

```python
# 올바른 패턴: session 접근 방어 코드 필수
session = getattr(http_client, "s", None)
if session is None:
    context_logger.error("HTTPClient must expose an underlying session via attribute 's'.")
    return results
```

- `http_client.s` 가 `requests.Session` 인스턴스
- `timeout` 파라미터를 항상 명시 (`plugin_config.timeout` 또는 기본값 10 사용)

---

## 6단계: 타입 힌트 및 가독성

### 확인 항목

- 모든 함수에 인자 타입과 반환 타입 힌트가 있는가
- `from typing import List, Optional, Any, Dict` 를 `typing` 모듈에서 임포트
  (Python 3.9+ 라도 프로젝트 기존 스타일인 `typing` 모듈 임포트 방식을 따른다)
- 매직 리터럴(하드코딩 문자열, 숫자)은 상수 또는 Enum으로 추출되어 있는가
  - `csrf_constants.py` 패턴 참고: 키워드 목록을 별도 파일로 분리
- 함수가 50줄을 초과하면 분리 가능 여부를 검토

---

## 7단계: 테스트 코드 검토

### 신규 플러그인 / 스캔 함수 추가 시

테스트 파일은 `test/unit/test_<plugin_name>_scan.py` 패턴으로 생성한다.

**최소 요구 테스트 케이스**

| 케이스 | 설명 |
|---|---|
| 취약점 미발견 | 정상 응답에서 `Severity.INFO` Finding 반환 |
| 취약점 발견 | 취약한 응답에서 적절한 `Severity` Finding 반환 |
| HTTP 오류 | `session`이 `None`이거나 요청 실패 시 빈 리스트 반환 |

**Fixture 사용 규칙**

```python
# conftest.py의 create_plugin_context() 또는 plugin_context_factory 픽스처를 사용
from test.conftest import create_plugin_context

def test_scan_returns_finding(responses_mock):
    responses_mock.add(responses.GET, "http://example.com", body="<html></html>")
    ctx = create_plugin_context(target_urls=["http://example.com"])
    ...
```

- HTTP 목업은 `responses` 라이브러리 사용 (`responses_mock` 픽스처)
- 실제 네트워크 요청을 하는 테스트는 허용하지 않는다

---

## 8단계: 보안 로직 검토 (플러그인 특화)

스캐너 플러그인이므로 스캔 로직 자체의 정확성도 검토한다.

### 오탐(False Positive) 위험

- 키워드 매칭 시 대소문자 정규화 (`html.lower()` 후 비교)
- 부분 문자열 매칭이 의도한 동작인지 확인 (예: `"token"` 이 `"tokenizer"` 도 매칭)

### 미탐(False Negative) 위험

- 멀티 레이어 검사(HTML body, 헤더, form 태그)가 누락된 레이어 없이 수행되는가
- `results.extend([...])` 로 모든 검사 결과가 수집되는가

### 페이로드 안전성

- 실제 공격 페이로드를 전송하지 않아야 한다 (passive scan 원칙)
- `csrf_scan.py` 처럼 토큰 존재 여부만 확인하는 방식을 따른다

---

## 9단계: 의존성 변경 검토

`pyproject.toml` 또는 `requirements*.txt` 가 변경된 경우:

- 신규 의존성의 라이선스가 MIT/Apache/BSD 계열인지 확인
- `requires-python = ">=3.9"` 과 호환되는 버전인지 확인
- dev 전용 의존성은 `pyproject.toml`의 `[project.optional-dependencies] dev` 또는 `requirements-dev.txt`에만 추가

---

## 리뷰 체크리스트 요약

```
[ ] 테스트 전체 통과
[ ] syntax 오류 없음
[ ] Finding 필수 필드 누락 없음
[ ] PluginContext.logger None 방어 처리
[ ] frozen dataclass 수정 시도 없음
[ ] 플러그인 함수 시그니처 일치
[ ] 에러 처리: 최외곽 except + 빈 리스트 반환
[ ] timeout 파라미터 명시
[ ] 타입 힌트 완비
[ ] 신규 스캔 로직에 대한 unit test 존재
[ ] responses 목업으로 실제 네트워크 미사용
[ ] passive scan 원칙 준수 (실제 공격 페이로드 없음)
```
