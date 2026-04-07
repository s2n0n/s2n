"""
Path Traversal Plugin

ATT&CK Mapping:
  TID    : T1083
  Name   : File and Directory Discovery
  Tactic : Discovery

웹 애플리케이션이 사용자 입력을 파일 경로로 처리할 때 디렉토리 순회 문자
(../  ..\\ 및 인코딩 변형)를 검증하지 않아 발생하는 취약점을 탐지한다.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from s2n.s2nscanner.interfaces import (
    PluginConfig,
    PluginContext,
    PluginError,
    PluginResult,
    PluginStatus,
)
from s2n.s2nscanner.plugins.helper import resolve_client, resolve_depth, resolve_target_url
from s2n.s2nscanner.logger import get_logger
from s2n.s2nscanner.plugins.path_traversal.path_traversal_scan import scan_path_traversal

logger = get_logger("plugins.path_traversal")


class PathTraversalPlugin:
    name = "path_traversal"
    description = (
        "Detects Path Traversal vulnerabilities (ATT&CK T1083 — "
        "File and Directory Discovery). Tests URL query parameters for "
        "directory traversal sequences that expose server-side files."
    )
    version = "0.1.0"

    def __init__(self, config: Optional[PluginConfig] = None):
        self.config = config or {}
        self.depth = int(
            getattr(self.config, "custom_params", {}).get("depth", 2)
            if hasattr(self.config, "custom_params")
            else 2
        )

    def run(self, plugin_context: PluginContext) -> PluginResult:
        start_time = datetime.now()
        findings = []

        try:
            http_client = resolve_client(self, plugin_context)
            target_url = resolve_target_url(self, plugin_context)
            depth = resolve_depth(self, plugin_context)

            findings = scan_path_traversal(
                target_url=target_url,
                http_client=http_client,
                plugin_context=plugin_context,
                depth=depth,
            )

            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.PARTIAL if findings else PluginStatus.SUCCESS,
                findings=findings,
                start_time=start_time,
                end_time=datetime.now(),
                duration_seconds=(datetime.now() - start_time).total_seconds(),
            )

        except Exception as e:
            logger.exception("[path_traversal] plugin error: %s", e)
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILED,
                findings=findings,
                start_time=start_time,
                end_time=datetime.now(),
                duration_seconds=(datetime.now() - start_time).total_seconds(),
                error=PluginError(
                    error_type=type(e).__name__,
                    message=str(e),
                ),
            )


def main(config: Optional[PluginConfig] = None) -> PathTraversalPlugin:
    return PathTraversalPlugin(config)
