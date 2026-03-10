#!/usr/bin/env python3
"""
S2N Scanner - Native Messaging Host
====================================
Chrome Extension과 로컬 Python 스캐너 사이의 브릿지 어댑터.
Chrome Native Messaging 프로토콜(4바이트 little-endian length prefix + JSON)을 사용하여
stdin/stdout으로 통신합니다.

사용법:
  이 스크립트는 Chrome이 Native Messaging Host로 직접 실행합니다.
  수동 테스트: echo '{"action":"ping"}' | python native_host.py
"""

import json
import struct
import sys
import traceback
from typing import Any, Dict, Optional


# ============================================================================
# Chrome Native Messaging 프로토콜 구현
# ============================================================================

def read_message() -> Optional[Dict[str, Any]]:
    """
    stdin에서 Chrome NM 프로토콜 메시지를 읽습니다.
    프로토콜: 4바이트 little-endian unsigned int (메시지 길이) + JSON bytes
    
    Returns:
        파싱된 JSON dict 또는 EOF 시 None
    """
    # 4바이트 길이 헤더 읽기
    raw_length = sys.stdin.buffer.read(4)
    if not raw_length or len(raw_length) < 4:
        return None

    # little-endian unsigned int로 길이 디코딩
    message_length = struct.unpack('<I', raw_length)[0]

    if message_length == 0:
        return None

    # 메시지 길이 제한 (1MB) - 악의적 입력 방어
    if message_length > 1024 * 1024:
        log_error(f"메시지 크기 초과: {message_length} bytes")
        return None

    # JSON body 읽기
    raw_message = sys.stdin.buffer.read(message_length)
    if len(raw_message) < message_length:
        log_error(f"불완전한 메시지: expected={message_length}, got={len(raw_message)}")
        return None

    return json.loads(raw_message.decode('utf-8'))


def write_message(message: Dict[str, Any]) -> None:
    """
    stdout으로 Chrome NM 프로토콜 메시지를 씁니다.
    프로토콜: 4바이트 little-endian unsigned int (메시지 길이) + JSON bytes
    """
    encoded = json.dumps(message, ensure_ascii=False).encode('utf-8')
    length = len(encoded)

    # 4바이트 길이 헤더 + JSON body 쓰기
    sys.stdout.buffer.write(struct.pack('<I', length))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


def encode_message(message: Dict[str, Any]) -> bytes:
    """
    메시지를 Chrome NM 프로토콜 바이트로 인코딩합니다.
    테스트 유틸리티 용도.
    
    Returns:
        4바이트 length prefix + JSON bytes
    """
    encoded = json.dumps(message, ensure_ascii=False).encode('utf-8')
    return struct.pack('<I', len(encoded)) + encoded


def decode_message(data: bytes) -> Dict[str, Any]:
    """
    Chrome NM 프로토콜 바이트를 메시지로 디코딩합니다.
    테스트 유틸리티 용도.
    
    Returns:
        파싱된 JSON dict
    """
    if len(data) < 4:
        raise ValueError(f"데이터가 너무 짧습니다: {len(data)} bytes")
    
    message_length = struct.unpack('<I', data[:4])[0]
    json_data = data[4:4 + message_length]
    
    if len(json_data) < message_length:
        raise ValueError(f"불완전한 메시지: expected={message_length}, got={len(json_data)}")
    
    return json.loads(json_data.decode('utf-8'))


# ============================================================================
# 로깅 (stderr → Chrome이 무시, 디버그용)
# ============================================================================

def log_info(msg: str) -> None:
    """정보 로그를 stderr로 출력합니다."""
    sys.stderr.write(f"[S2N-Host INFO] {msg}\n")
    sys.stderr.flush()


def log_error(msg: str) -> None:
    """에러 로그를 stderr로 출력합니다."""
    sys.stderr.write(f"[S2N-Host ERROR] {msg}\n")
    sys.stderr.flush()


# ============================================================================
# 액션 핸들러
# ============================================================================

def handle_ping() -> Dict[str, Any]:
    """ping 요청에 pong으로 응답합니다."""
    return {
        "status": "ok",
        "action": "pong",
    }


def handle_get_version() -> Dict[str, Any]:
    """스캐너 버전 정보를 반환합니다."""
    try:
        from importlib import metadata as importlib_metadata
        version = importlib_metadata.version("s2n")
    except Exception:
        version = "unknown"

    return {
        "status": "ok",
        "action": "version",
        "data": {
            "version": version,
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        },
    }


def handle_unknown(action: str) -> Dict[str, Any]:
    """알 수 없는 액션에 대한 에러 응답을 반환합니다."""
    return {
        "status": "error",
        "action": action,
        "error": f"Unknown action: {action}",
    }


# 액션 라우팅 테이블
ACTION_HANDLERS = {
    "ping": handle_ping,
    "get_version": handle_get_version,
}


def dispatch(message: Dict[str, Any]) -> Dict[str, Any]:
    """
    수신 메시지의 action 필드를 기반으로 적절한 핸들러로 라우팅합니다.
    
    Args:
        message: Chrome에서 수신한 JSON 메시지 (action 필드 필수)
    
    Returns:
        핸들러의 응답 dict
    """
    action = message.get("action", "")

    handler = ACTION_HANDLERS.get(action)
    if handler:
        return handler()
    
    return handle_unknown(action)


# ============================================================================
# 메인 루프
# ============================================================================

def main() -> None:
    """
    Native Messaging Host 메인 루프.
    stdin에서 메시지를 읽고, action별 핸들러로 라우팅하고, stdout으로 응답합니다.
    
    Chrome이 프로세스를 종료하면(stdin EOF) 자연스럽게 종료됩니다.
    """
    log_info("S2N Native Messaging Host started.")

    while True:
        try:
            message = read_message()

            # EOF → Chrome이 연결을 종료함
            if message is None:
                log_info("stdin EOF. Shutting down.")
                break

            log_info(f"Received: {json.dumps(message, ensure_ascii=False)}")

            # 액션 디스패치
            response = dispatch(message)
            write_message(response)

            log_info(f"Sent: {json.dumps(response, ensure_ascii=False)}")

        except json.JSONDecodeError as e:
            log_error(f"JSON 파싱 실패: {e}")
            write_message({
                "status": "error",
                "error": f"Invalid JSON: {e}",
            })

        except Exception as e:
            log_error(f"예기치 않은 오류: {e}\n{traceback.format_exc()}")
            try:
                write_message({
                    "status": "error",
                    "error": f"Internal error: {e}",
                })
            except Exception:
                # stdout도 깨진 경우 조용히 종료
                break


if __name__ == "__main__":
    main()
