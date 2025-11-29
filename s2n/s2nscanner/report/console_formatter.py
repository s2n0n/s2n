# 콘솔 데이터 구성

"""
Console Formatter Module

ScanReport 객체를 콘솔 출력용 문자열로 변환하는 기능을 제공합니다.
파일 저장은 하지 않으며, format()은 출력 문자열을 반환합니다.
"""

from __future__ import annotations
import io
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

from s2n.s2nscanner.interfaces import (
    ScanReport,
    Severity,
    ConsoleMode,
    PluginStatus,
)
from s2n.s2nscanner.report.base import ReportFormatter


class ConsoleFormatter(ReportFormatter):
    """
    Console 형식 Formatter

    기능:
    - ScanReport → 콘솔 요약/상세 문자열 생성 (Rich 라이브러리 사용)
    - save()는 no-op 처리
    """

    def __init__(self, mode: ConsoleMode = ConsoleMode.SUMMARY):
        self.mode = mode

    def format(self, report: ScanReport) -> str:
        """ScanReport를 Rich 라이브러리를 사용하여 스타일링된 문자열로 변환"""
        
        # Capture rich output to string
        buffer = io.StringIO()
        console = Console(file=buffer, force_terminal=True, width=100)

        # 1. Summary Table
        target_url = report.target_url
        duration_seconds = report.duration_seconds
        
        duration_text = (
            f"{duration_seconds:.2f} seconds"
            if isinstance(duration_seconds, (int, float))
            else "-"
        )

        plugin_results = report.plugin_results or []
        total_findings = 0
        for pr in plugin_results:
            findings = getattr(pr, "findings", []) or []
            total_findings += len(findings)

        summary_table = Table(
            title="🚀 S2N Scan Summary",
            title_style="bold magenta",
            box=box.SIMPLE_HEAVY,
            show_header=False,
            padding=(0, 1),
        )
        summary_table.add_row("🎯 Target URL", f"[bold]{target_url}[/]")
        summary_table.add_row("🆔 Scan ID", getattr(report, "scan_id", "-"))
        summary_table.add_row(" ⏱ Duration", duration_text)
        summary_table.add_row("🧩 Plugins Loaded", str(len(plugin_results)))
        summary_table.add_row(
            "🔎 Findings Detected", f"[bold yellow]{total_findings}[/]"
        )
        
        # Summary Data from report.summary if available
        if report.summary:
            s = report.summary
            summary_table.add_row("📊 Success Rate", f"{s.success_rate:.1f}%")
            summary_table.add_row("🌐 URLs Scanned", str(s.total_urls_scanned))

        console.print("\n")
        console.print(summary_table)

        # 2. Plugin Results Table
        status_styles = {
            PluginStatus.SUCCESS: "green",
            PluginStatus.PARTIAL: "yellow",
            PluginStatus.FAILED: "red",
            PluginStatus.SKIPPED: "cyan",
            PluginStatus.TIMEOUT: "magenta",
        }
        status_icons = {
            PluginStatus.SUCCESS: "✅",
            PluginStatus.PARTIAL: "🟡",
            PluginStatus.FAILED: "❌",
            PluginStatus.SKIPPED: "⏩",
            PluginStatus.TIMEOUT: "⏰",
        }

        plugin_table = Table(
            title="🧩 Plugin Results",
            title_style="bold cyan",
            box=box.MINIMAL_HEAVY_HEAD,
            header_style="bold white",
        )
        plugin_table.add_column("Plugin")
        plugin_table.add_column("Status", justify="center")
        plugin_table.add_column("Findings", justify="right")
        plugin_table.add_column("Duration", justify="right")
        plugin_table.add_column("Note")

        for pr in plugin_results:
            status = getattr(pr, "status", None)
            status_color = status_styles.get(status, "white")
            icon = status_icons.get(status, "ℹ️")
            note = "-"
            metadata = getattr(pr, "metadata", None) or {}
            note = metadata.get("reason", note)
            if getattr(pr, "error", None):
                note = getattr(pr.error, "message", note)

            plugin_table.add_row(
                f"{icon} {getattr(pr, 'plugin_name', '-')}",
                f"[{status_color}]{getattr(status, 'value', status or '-')}[/{status_color}]",
                str(len(getattr(pr, "findings", []) or [])),
                f"{getattr(pr, 'duration_seconds', 0):.2f}s"
                if isinstance(getattr(pr, "duration_seconds", None), (int, float))
                else "-",
                note or "-",
            )

        if plugin_results:
            console.print("\n")
            console.print(plugin_table)
            console.print("\n")

        # 3. Detailed Findings (if verbose)
        if self.mode in [ConsoleMode.VERBOSE, ConsoleMode.DEBUG]:
            console.print("[bold underline]Detailed Findings[/bold underline]\n")
            
            for plugin_result in report.plugin_results:
                if plugin_result.findings:
                    console.print(f"[bold cyan]Plugin: {plugin_result.plugin_name}[/bold cyan]")
                    
                    for f in plugin_result.findings:
                        severity_color = "white"
                        if f.severity == Severity.CRITICAL:
                            severity_color = "red bold"
                        elif f.severity == Severity.HIGH:
                            severity_color = "red"
                        elif f.severity == Severity.MEDIUM:
                            severity_color = "yellow"
                        elif f.severity == Severity.LOW:
                            severity_color = "blue"
                        
                        console.print(f"  [{severity_color}][{f.severity.value}] {f.title}[/{severity_color}]")
                        if f.url:
                            console.print(f"    URL: {f.url}")
                        if f.parameter:
                            console.print(f"    Parameter: {f.parameter}")
                        if f.payload:
                            console.print(f"    Payload: {f.payload}")
                        console.print("")

        return buffer.getvalue()

    def save(self, report: ScanReport, path: Path):
        # no-op
        pass

