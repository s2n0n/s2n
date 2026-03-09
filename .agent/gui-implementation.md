---
name: S2N GUI Implementation Skill
description: 브라우저(Chrome Extension) 환경에서 S2N 취약점 스캐너 실행을 제어하기 위한 GUI 개발 및 아키텍처 가이드
---

# S2N GUI Implementation Skill

본 스킬 매뉴얼은 에이전트가 S2N 스캐너의 브라우저 확장 프로그램(Chrome Extension) GUI를 개발하고 유지보수할 때 반드시 준수해야 하는 기술적 지침과 아키텍처 제약 사항을 정의합니다.

## 1. 핵심 제약 및 원칙 (Core Constraints)

- **s2nscanner 코어 코드 수정 금지 (Zero Modification):** 기존 파이썬 스캐너 엔진(`s2nscanner`)은 절대 수정하지 않습니다. 모든 연동은 인터페이스와 브릿지(Bridge)를 통해서만 수행합니다.
- **Native Messaging 통신 필수:** 브라우저 CORS 제약 및 원시 소켓 사용 불가 문제를 피해 로컬 네트워크 환경을 100% 활용하기 위해, WebAssembly(Pyodide) 방식은 **기각**하고 반드시 **Chrome Native Messaging API**를 사용합니다.
- **의존성 분리:** `s2nscanner` 패키지 외부에서 동작하는 `native_host.py`를 단일 브릿지 어댑터로 생성하여 사용합니다.

## 2. 기술 스택 (Tech Stack)

GUI 개발 시 다음 기술 스택을 엄격히 적용하여 최고 수준의 프리미엄 UI/UX를 제공합니다.

- **Frontend (Extension UI):** React, Tailwind CSS
- **UI Component:** Shadcn/ui (빠르고 일관된 모던 디자인 적용 - Button, Form, Table, Progress, Badge 등)
- **Backend Adapter:** Python 3.x (`native_host.py`)
- **Build System:** Vite 또는 Webpack

## 3. 시스템 아키텍처 및 데이터 흐름 (Architecture & Data Flow)

작업 시 다음의 통신/데이터 흐름 모델을 준수하여 로직을 구성하십시오:

1. **입력 체계 (React UI):** Extension Popup에서 스캔할 타겟(URL)과 설정을 JSON 형태로 구성.
2. **트리거 (Service Worker):** `chrome.runtime.sendNativeMessage` API 호출을 통해 파이썬 어댑터 프로세스 구동.
3. **스캔 실행 (Adapter Layer):** `native_host.py`가 JSON 인자를 `ScanConfig`로 매핑하고 `Scanner.scan()`을 호출하여 자체 네트워크로 취약점 점검을 수행.
4. **실시간 동기화 (IPC):** 스캐너의 `on_progress` 실시간 콜백에서 발생하는 진행률(%) 및 로그를 `sys.stdout` 파이프(JSON 포맷)를 통해 프론트엔드로 펌핑(Pumping)하고, React 단에서 프리미엄 진행률 바(Progress Bar)로 렌더링.
5. **결과 처리:** 스캔 완료 시 최종 결과(Report JSON)를 수신받고, Options 페이지에서 Table 및 Accordion으로 데이터 시각화.

## 4. 단계별 실행 가이드 (Implementation Phases)

에이전트는 다음 이정표에 따라 GUI 작업을 수행하고 단계별 검증 절차를 거칩니다.

### Phase 1: 기반 설정 및 UI 뼈대 구성

- Manifest V3 설정 내역에 `nativeMessaging` 호스트 권한 추가.
- React 기반 Extension 앱 생성, Tailwind CSS + Shadcn/ui 필수 컴포넌트 셋업.

### Phase 2: 어댑터 생성 및 통신 인프라 구축

- S2N 패키지를 `import`하여 스캐너를 래핑하는 `native_host.py` 브릿지 스크립트 작성 (`sys.stdin` / `stdout` 입출력, JSON 직렬화).
- OS별(Mac/Win) 레지스트리 및 Native Host JSON 파일 등록 스크립트 작성.
- 브라우저 프론트엔드와 어댑터 간 양방향 JSON 통신 연결성 검증용 핑퐁 테스트(Mock Test) 진행.

### Phase 3: 프론트엔드 핵심 뷰(View) 개발

- **Quick Action Popup:** 스캔 대상 URL 입력창, 스캔 설정 선택 폼 및 스캔 시작/취소 제어 인터페이스 구현.
- **Scan Board (Options UI):** 심도 있는 스캔 진행 뷰어 및 상세 취약점 리포트 시각화(Badge 심각도 표현, 결과 Table, 상세 내역 Expandable Card).

### Phase 4: 라이프사이클 관리 및 안정성(Release) 최적화

- 스캐너 중단 등 비동기 취소 로직 처리 및 IPC 타임아웃/오류 복구, 에러 바운더리 UX 적용.
- `chrome.storage.local`을 이용한 스캔 히스토리/결과 기록 및 다운로드 지원.
- 크롬 웹 스토어 심사 대응을 위해 매니페스트 권한 최소화 유지.

## 5. 최종 배포 및 설치 경험(User Flow) 가이드

1. **클라우드 비의존성 공지:** 웹 앱은 100% 로컬 환경에서 구동됨을 사용자에게 UX 상에서 명확히 안내해야 합니다.
2. **로컬 브릿지 제공:** 크롬 내 익스텐션(UI) 설치만으로는 스캐너 동작이 불가합니다. 사용자가 초기 진입 시 로컬에 `s2n-host` 런타임 및 `Native Messaging Manifest JSON` 환경을 설정해 주는 전용 인스톨러(OS 기반 Mac/Win 앱)를 다운로드할 수 있도록 유도해야 합니다.
3. **심사 소명 자료 검토:** `nativeMessaging` 사용 사유로 "로컬 네트워크 인프라를 활용하여 실질적인 취약점 스캐닝을 하기 위함"이라는 사용처와 데이터 보안 정책을 명시하도록 설계합니다.
