# GUI + Chrome Extension 개발 계획

## 1) 목표
CLI 없이도 사용자가 s2n 스캔을 실행하고, 진행 상태를 확인하고, 결과를 내보낼 수 있도록 Chrome Extension 기반 GUI를 구축한다. 별도의 클라우드 서버나 로컬 API 서버를 띄우지 않고, 크롬의 **Native Messaging API**를 활용해 OS 단의 Python 실행 파일과 익스텐션이 직접 통신하는 완전히 독립적인 로컬 환경을 제공한다.

## 2) 범위
- **포함 범위:**
  - Extension UI (Popup + Options 페이지)
  - 스캔 시작/중지 제어
  - 진행 상태 및 결과 요약 화면
  - JSON 내보내기 및 로컬 히스토리
  - 기본 설정 (대상 URL, 플러그인, timeout, depth)
  - Chrome Native Messaging 기반 통신 인터페이스 개발
  - PyInstaller를 이용한 Python 스캐너 론칭용 단일 실행 파일(`.exe` / 바이너리) 패키징

- **제외 범위(이번 단계):**
  - 스토어 배포 자동화
  - 팀 계정/과금 워크플로우
  - 다중 사용자 클라우드 동기화

## 3) 제품 방향
- **배포 형태:** Chrome Extension (Manifest V3) 및 배포용 로컬 셋업 파일
- **런타임 구성:**
  - **Popup:** 사용자 입력 및 빠른 실행
  - **Options 페이지:** 고급 설정 / 히스토리 데이터
  - **Background Service Worker:** 스캔 오케스트레이션 및 작업 생명주기 관리. `chrome.runtime.sendNativeMessage` API로 로컬 프로세스를 백그라운드로 호출한다.
  - **Native Messaging Host (Python App):** 웹훅이나 서버 없이 `sys.stdin`, `sys.stdout`으로 익스텐션과 JSON 기반으로 통신하여 스캐너 코어를 직접 실행하는 래퍼(Wrapper).

## 4) 아키텍처 초안
- **UI 계층 (Frontend):**
  - Popup: 시작/중지, 빠른 플러그인 선택, 최신 진행 상태 및 발견 사항(Finding) 시각화
  - Options: 전체 설정, 과거 결과 목록, 리포트 Export

- **애플리케이션 계층 (Extension 내부):**
  - **ScanController:** 입력 검증, 시작/중지 흐름 처리, Native Messaging 포트 연결 및 상태 전이.
  - **ResultStore:** 스캔 결과 정규화 및 빠르고 안정적인 `chrome.storage` 저장.
  - **ExportService:** 스캔 데이터를 JSON 리포트로 변환 및 다운로드 지원.

- **연동 계층 (Local OS):**
  - 스캐너 브릿지 작성: 익스텐션의 커맨드(`stdin`)를 받고 JSON 메시지 스트림(`stdout`)으로 프로그레스 및 결과를 반환하는 경계 정의.
  - timeout / retry 가드레일이 포함된 요청 큐 연동.
  - 스캔 실행 전 host permission 제약 검증.

## 5) 보안 및 권한
- **Manifest V3 최소 권한 원칙 적용.**
- `host_permissions`는 사용자가 선택한 대상 도메인만 허용하도록 구성.
- 브라우저 제약을 넘어 타겟 벤더 등에 안전하게 임의 페이로드를 전송하기 위해 OS의 로컬 소켓/네트워크 권한을 자유롭게 사용할 수 있는 Native Messaging 활용.
- 민감 정보(계정/토큰)는 영구 저장하지 않음 (메모리 기반 휘발성 유지 권장).
- 외부 도메인 스캔 전 명시적인 사용자 경고/동의 UX 제공 (사용자 승인 후 스캔).

## 6) UX 계획
- **주요 상태:**
  - Idle (대기)
  - Validating (설정/타겟 검증)
  - Scanning (실행 중 - Native Messaging 통신 중)
  - Completed (스캔 완료)
  - Failed (에러, 연결 유실 또는 타임아웃)

- **핵심 화면:**
  - Quick Scan (Popup에서 타겟 입력)
  - Scan Detail (실시간 진행률 + Finding 노출)
  - History & Export (Options 화면)
  - Settings (기본 대상/플러그인 옵션 설정 및 Native Host 설치 안내)

## 7) 마일스톤
- **M1: 기반 구성**
  - Extension 스켈레톤, Manifest 구성, Popup/Options 라우팅, 상태 모델 프레임워크 설정.
  - OS별 Native Messaging 권한 부여(매니페스트 설치) 및 통신 가능 여부 테스트.

- **M2: 스캔 플로우 연동**
  - Popup에서 시작/중지 버튼 기능 연결.
  - 로컬 스캐너 어댑터와의 실시간 Pipe 통신을 통한 진행 상태 수신.

- **M3: 결과 UX 및 로컬 패키징**
  - Finding 카드, 심각도(Severity) 필터, 상세 패널 구성.
  - PyInstaller를 사용해 S2N 파이썬 코드를 독립 바이너리로 단일 패키징하는 빌드 프로세스 마련.

- **M4: 안정화**
  - 에러 처리, 로컬 프로세스 크래시 대응, retry/timeout 동작 제어.
  - UX 상에서의 권한 관리 동작 QA.

- **M5: 릴리즈 준비**
  - 익스텐션(.zip/.crx) + 로컬 실행파일(인스톨러)의 배포 본 작성.
  - 버전 릴리즈 정책 및 변경 이력(changelog) 관리, 배포 가이드라인 작성.

## 8) 작업 분해
- **프론트엔드 (Extension 영역)**
  - Popup/Options UI 컴포넌트(배지, finding row 등) 구현.
  - 상태별 로딩, 인터랙션 및 오류 UX 화면 정의.

- **백엔드/어댑터 (로컬 파이썬 영역)**
  - Native Messaging Host 파이썬 스크립트 작성 (브릿지 계약 수립).
  - 기존 플러그인의 결과를 UI가 소비 가능한 JSON 모델로 정규화 및 스트림 반환.
  - 사용자 스캔 취소 요청(cancellation) 대응 로직 추가.

- **QA 계획**
  - DVWA와 같은 로컬 취약 서버 혹은 권한이 허가된 비취약 타겟(1곳 이상)으로 End-to-End 동작 점검.
  - 레지스트리/매니페스트 설치 문제로 인한 통신 실패 시 UI에 적절히 에러를 표현하는지 점검.

## 9) 리스크 및 대응
- **리스크 1: Chrome 익스텐션 - 로컬 프로세스간 통신 실패 (설정 요류)**
  - **대응:** 초심자도 설치 스크립트 하나로 설정을 해결할 수 있도록 지원하며, 실패 시 직관적인 가이드라인 표출.
- **리스크 2: 장시간 스캔 시 UI 멈춤 및 서비스 워커 슬립**
  - **대응:** 점진적(chunked) 진행도 업데이트를 활용하여 워커를 깨워두거나, 연결 재설정 기능 제공.
- **리스크 3: 플러그인별 고유 결과물 스키마의 다양성**
  - **대응:** 통합 정규화 계층(Adapter)을 거쳐 획일화된 구조(Title, Description, Status, Severity)를 갖추도록 설계.

## 10) 산출물
- 압축 해제 형태로 즉시 로드(Load Unpacked) 가능한 **Chrome Extension 프로토타입 디렉토리**
- 로컬에서 Python 및 의존성 설치 없이 동작하는 **S2N 코어 독립 실행 파일** 및 Native Messaging **인스톨 스크립트**
- 앱 내 **스캔 → 결과 확인 → 내보내기**의 완전한 GUI 워크플로우
- 확장 아키텍처 및 Native Messaging 인터페이스 통신 기술 설계 노트
