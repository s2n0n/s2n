## 🧩 배포 방식 설계서
> [FEAT]: 서버가 필요 없는 로컬 크롬 익스텐션 배포 방식(Native Messaging) 설계서 추가

---

## 개요 (Overview)
클라우드 서버나 별도의 로컬 API 서버(FastAPI 등)를 띄우지 않고, **Chrome Extension과 로컬 Python 스크립트가 직접 통신**하여 S2N 스캐너를 구동하는 배포 방식(Native Messaging)을 조사하고 설계했습니다.
이를 통해 클라우드 유지비용을 없애고, 사용자의 로컬 자원만으로 익스텐션에서 스캐너를 바로 실행할 수 있도록 아키텍처를 재설계했습니다.

---

## 변경 사항 (Changes)

### 1. 배포 방식 변경: Chrome Native Messaging 도입
- 기존의 HTTP 기반 통신(Extension <-> 백엔드 API 서버) 대신, 크롬의 **Native Messaging API**를 활용합니다.
- 익스텐션이 운영체제(OS) 환경에 설치된 Python 실행 파일을 직접 호출하고(표준 입출력을 통해) 스캔 결과를 주고받는 구조입니다.

### 2. 아키텍처 및 통신 구조 설계
- **Frontend (Chrome Extension)**: 사용자 UI를 제공하며 `chrome.runtime.sendNativeMessage` API를 사용하여 백그라운드로 실행 권한을 가진 로컬 Python 프로세스에 스캔 타겟 및 페이로드를 전달합니다.
- **Native Messaging Host (Python App)**: 클라우드나 웹 서버 레이어 없이 `sys.stdin`, `sys.stdout`을 통해 익스텐션과 JSON 데이터를 직접 교환하는 래퍼(Wrapper) 스크립트 작성합니다. 내부적으로 기존 S2N 스캐너 코어를 호출합니다.

### 3. 패키징 및 배포 방법 (PyInstaller + Extension 설치 파일)
- Python 코드를 설치하지 않아도 되도록 **PyInstaller**를 사용하여 S2N 스캐너 로직과 Native Messaging Host 스크립트를 하나의 단일 실행 파일(`.exe` 또는 바이너리)로 래핑 및 패키징합니다.
- 사용자에게 배포할 파일 구성:
  1. 패키징된 스캐너 실행 파일 (S2N Core)
  2. Native Messaging 권한을 부여하는 레지스트리/매니페스트 설정 스크립트 (Install script)
  3. Chrome Extension 파일 (`.crx` 또는 웹스토어 링크)
- 사용자는 최소 한 번 로컬 런타임용 셋업(인스톨러)을 실행한 후, 브라우저 익스텐션 버튼으로 스캐너를 바로 사용하게 됩니다.

---

## ✅ 체크리스트 (Checklist)
- [x] 클라우드(서버)가 불필요한 독립형 로컬 구동 아키텍처 조사 완료
- [x] 크롬 익스텐션과 로컬 프로세스 간의 통신(Native Messaging) 구조 설계
- [x] 단일 실행 파일 래핑(PyInstaller) 및 배포 아이디어 구체화

---

## 🔍 관련 이슈 (Issue)
> 

---

## 💬 비고 (Notes)
클라우드를 쓰지 않고 익스텐션을 쓰려면 순수 자바스크립트 변환이나 WebAssembly(Pyodide) 방식도 존재하나, 웹 스캐너 특성상 브라우저의 CORS 정책(보안 제약) 등으로 인해 타겟 사이트에 임의의 페이로드를 보내기 까다롭습니다. 
따라서 OS의 네트워크 소켓을 자유롭게 쓸 수 있는 **Native Messaging 방식 (로컬 실행 파일을 익스텐션이 백그라운드에서 직접 호출하는 방식)**이 가장 적합하고 현실적인 대안입니다.
패키징 시 파이썬 의존성 문제를 해결하기 위해 PyInstaller나 Nuitka로 완전히 단일 바이너리로 묶어 배포하는 스크립트가 추가적으로 필요합니다.
