"""
Sensitive File Exposure Plugin

ATT&CK Mapping:
  TID    : T1552.001
  Name   : Unsecured Credentials: Credentials In Files
  Tactic : Credential Access

웹 루트에 실수로 노출된 .env, .git/config, wp-config.php 등
민감 파일을 탐지하고 자격증명 포함 여부를 2차 검증한다.
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
from s2n.s2nscanner.plugins.helper import resolve_client, resolve_target_url
from s2n.s2nscanner.logger import get_logger
from s2n.s2nscanner.plugins.sensitive_files.sensitive_files_scan import scan_sensitive_files

logger = get_logger("plugins.sensitive_files")


class SensitiveFilesPlugin:
    name = "sensitive_files"
    description = (
        "Detects exposed sensitive files (ATT&CK T1552.001 — "
        "Credentials In Files). Probes for .env, .git/config, "
        "wp-config.php, DB backups, SSH keys, and similar files "
        "accessible from the web root without authentication."
    )
    version = "0.1.0"

    def __init__(self, config: Optional[PluginConfig] = None):
        self.config = config
        # depth는 이 플러그인에서 사용하지 않음 (파일 목록 기반 탐지)
        self.depth = 2

    def run(self, plugin_context: PluginContext) -> PluginResult:
        start_time = datetime.now()
        findings = []

        try:
            http_client = resolve_client(self, plugin_context)
            target_url = resolve_target_url(self, plugin_context)

            findings = scan_sensitive_files(
                target_url=target_url,
                http_client=http_client,
                plugin_context=plugin_context,
            )

            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.PARTIAL if findings else PluginStatus.SUCCESS,
                findings=findings,
                start_time=start_time,
                end_time=datetime.now(),
                duration_seconds=(datetime.now() - start_time).total_seconds(),
                requests_sent=0,  # scan 함수 내부에서 요청 수 추적하지 않음
            )

        except Exception as e:
            logger.exception("[sensitive_files] plugin error: %s", e)
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


def main(config: Optional[PluginConfig] = None) -> SensitiveFilesPlugin:
    return SensitiveFilesPlugin(config)
