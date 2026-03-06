# GUI + Chrome Extension 개발 계획 (JH)

## 1) 목표
CLI 없이도 사용자가 s2n 스캔을 실행하고, 진행 상태를 확인하고, 결과를 내보낼 수 있도록  
Chrome Extension 기반 GUI를 구축한다.

## 2) 범위
- 포함 범위:
- Extension UI (Popup + Options 페이지)
- 스캔 시작/중지 제어
- 진행 상태 및 결과 요약 화면
- JSON 내보내기 및 로컬 히스토리
- 기본 설정(대상 URL, 플러그인, timeout, depth)

- 제외 범위(이번 단계):
- 스토어 배포 자동화
- 팀 계정/과금 워크플로우
- 다중 사용자 클라우드 동기화

## 3) 제품 방향
- 배포 형태: Chrome Extension (Manifest V3)
- 런타임 구성:
- Popup: 사용자 입력 및 빠른 실행
- Options 페이지: 고급 설정/히스토리
- Background Service Worker: 스캔 오케스트레이션 및 작업 생명주기 관리
- Content Script: 페이지 레벨 데이터 추출이 필요할 때만 사용

## 4) 아키텍처 초안
- UI 계층:
- Popup: 시작/중지, 빠른 플러그인 선택, 최신 상태 표시
- Options: 전체 설정, 결과 목록, 리포트 내보내기

- 애플리케이션 계층:
- ScanController: 입력 검증, 시작/중지 흐름, 상태 전이 관리
- ResultStore: 결과 정규화 및 `chrome.storage` 저장
- ExportService: JSON 리포트 생성 및 다운로드

- 연동 계층:
- 스캐너 실행 어댑터 경계 정의
- timeout/retry 가드레일이 있는 요청 큐
- 스캔 실행 전 host permission 검증

## 5) 보안 및 권한
- Manifest V3 최소 권한 원칙 적용
- `host_permissions`는 사용자가 선택한 대상 도메인만 허용
- 민감 정보(계정/토큰)는 기본 영구 저장 금지
- 가능하면 인증 정보는 메모리 기반으로 처리
- 외부 도메인 스캔 전 명시적 경고/동의 UX 제공

## 6) UX 계획
- 주요 상태:
- Idle
- Validating
- Scanning
- Completed
- Failed

- 핵심 화면:
- Quick Scan (Popup)
- Scan Detail (진행률 + Finding)
- History & Export (Options)
- Settings (기본 대상/플러그인 설정)

## 7) 마일스톤
- M1: 기반 구성
- Extension 스켈레톤, Manifest, Popup/Options 라우팅, 상태 모델 구성

- M2: 스캔 플로우
- 시작/중지 제어, 스캐너 어댑터 연결, 진행 상태 스트림 구현

- M3: 결과 UX
- Finding 카드, 심각도 필터, 상세 패널, JSON 내보내기 구현

- M4: 안정화
- 에러 처리, 권한 UX, retry/timeout 동작, QA 체크리스트 정리

- M5: 릴리즈 준비
- 버전 정책, 변경 이력(changelog), 패키지 검증, 내부 배포 가이드

## 8) 작업 분해
- 프론트엔드
- Popup/Options UI 구현
- 공통 컴포넌트(상태 배지, finding row, 필터) 구현
- 상태 전이 및 로딩/오류 UX 구현

- 백엔드/어댑터
- 스캐너 브릿지 계약(인터페이스) 정의
- 플러그인 결과를 UI 모델로 정규화
- 취소(cancellation) 및 timeout 동작 구현

- QA
- 로컬 DVWA + 비취약 타겟 최소 1개에서 동작 점검
- 권한 요청/차단 도메인 처리 UX 점검
- 리포트 내보내기 및 히스토리 재조회 무결성 점검

## 9) 리스크 및 대응
- 리스크: CORS/권한 불일치
- 대응: 사전 host 체크 + 명확한 권한 요청 UX

- 리스크: 장시간 스캔 시 UI 멈춤
- 대응: Background Worker 기반 처리 + 점진적 진행 업데이트

- 리스크: 플러그인별 결과 스키마 드리프트
- 대응: 엄격한 결과 정규화 계층 + 버전 기반 매핑 관리

## 10) 산출물
- 로드 가능한(압축 해제 설치) Chrome Extension 프로토타입
- 스캔 → 결과 확인 → 내보내기 GUI 워크플로우
- 확장 아키텍처 기술 설계 노트