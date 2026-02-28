from __future__ import annotations
import click
from datetime import datetime

from s2n.s2nscanner.interfaces import (
    CLIArguments,
    ScanContext,
    ProgressInfo,
    PluginStatus,
)
from s2n.s2nscanner.cli.mapper import cliargs_to_scanrequest
from s2n.s2nscanner.cli.config_builder import build_scan_config
from s2n.s2nscanner.auth.dvwa_adapter import DVWAAdapter
from s2n.s2nscanner.scan_engine import Scanner
from s2n.s2nscanner.report import output_report, OutputFormat
from s2n.s2nscanner.logger import init_logger

import os
from rich.console import Console
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich import box

# Docker/CI 환경에서도 rich가 작동하도록 설정
# force_terminal=True: TTY가 없어도 터미널 기능 활성화
# force_interactive=False: CI 환경에서 인터랙티브 기능 비활성화
is_ci = os.getenv("CI", "").lower() in ("true", "1", "yes")
console = Console(force_terminal=True, force_interactive=not is_ci)


# CLI Root
@click.group()
def cli():
    ascii_logo = r"""
    (`-').->        <-. (`-')_
    ( OO)_             \( OO) )
    (_)--\_)  .----. ,--./ ,--/
    /    _ / \_,-.  ||   \ |  |
    \_..`--.    .' .'|  . '|  |)
    .-._)   \ .'  /_ |  |\    |
    \       /|      ||  | \   |
    `-----' `------'`--'  `--'

    S2N Web Vulnerability Scanner CLI
    """

    colored_logo = click.style(ascii_logo, fg="blue", bold=True)
    click.echo(colored_logo)
    click.echo("🔍 Welcome to S2N Scanner! Use --help to explore commands.\n")


# scan 명령어
@cli.command("scan")
@click.option("-u", "--url", required=True, help="""Target URL to scan\n스캔 대상 URL""")
@click.option(
    "-p",
    "--plugin",
    multiple=True,
    help="Plugins to use (can be used multiple times). If omitted or if --all is used, all plugins except soft_brute_force will run. \n사용할 플러그인 이름. 생략하거나 --all 사용 시 전체 플러그인(soft_brute_force 제외)이 실행됩니다. \n\n[options: csrf, sqlinjection, file_upload, oscommand, xss, brute_force, soft_brute_force]",
)
@click.option(
    "--all", "run_all", is_flag=True, help="Run all default plugins / 모든 기본 플러그인 실행"
)
@click.option(
    "-a",
    "--auth",
    help="Authentication type \n인증 타입 \n\n(NONE, BASIC, BEARER, DVWA, etc.)",
)
@click.option(
    "-y", "--accept-risk", is_flag=True, help="Automatically bypass brute force warning / 무차별 대입 공격 경고 자동 동의"
)
@click.option("--username", help="Username for authentication \n인증용 사용자명")
@click.option("--password", help="Password for authentication \n인증용 비밀번호")
@click.option(
    "-o", "--output", help="Output file path (e.g., result.json) \n 결과 출력 파일 경로"
)
@click.option(
    "--output-format",
    type=click.Choice([fmt.value for fmt in OutputFormat], case_sensitive=False),
    default=OutputFormat.JSON.value,
    show_default=True,
    help="Output format / 결과 출력 형식 (JSON, HTML, CSV, CONSOLE, MULTI)",
)
@click.option("--crawler-depth", default=2, help="Crawler depth / 크롤러 탐색 깊이")
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging / 상세 로그 출력")
@click.option("--log-file", help="Log file path / 로그 파일 경로")
def scan(
    url,
    plugin,
    run_all,
    auth,
    username,
    password,
    output,
    output_format,
    crawler_depth,
    verbose,
    log_file,
    accept_risk,
):
    logger = init_logger(verbose, log_file)
    logger.info("Starting scan for %s", url)

    # --all 플래그 처리 및 --plugin 생략 처리
    plugin_list = list(plugin)
    if run_all or not plugin_list:
        plugin_list = ["csrf", "sqlinjection", "file_upload", "oscommand", "xss", "brute_force"]

    # CLIArguments 구성
    args = CLIArguments(
        url=url,
        plugin=plugin_list,
        auth=auth,
        username=username,
        password=password,
        output=output,
        output_format=output_format,
        depth=crawler_depth,
        verbose=verbose,
        log_file=log_file,
        accept_risk=accept_risk,
    )

    request = cliargs_to_scanrequest(args)
    config = build_scan_config(request, username=username, password=password)

    # 인증 처리 (DVWA)
    http_client = None
    auth_adapter = None
    auth_credentials = None

    if (auth or "").lower() == "dvwa":
        logger.info("DVWA authentication requested.")
        auth_adapter = DVWAAdapter(base_url=request.target_url)
        username = username or "admin"
        password = password or "password"

        auth_credentials = [(username, password)]

        if auth_adapter.ensure_authenticated(auth_credentials):
            http_client = auth_adapter.get_client()
            logger.info("DVWA 로그인 완료")
        else:
            logger.warning("DVWA 로그인 실패 - 인증 없이 진행")

    # ScanContext 생성
    scan_ctx = ScanContext(
        scan_id=f"scan-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        start_time=datetime.utcnow(),
        config=config,
        http_client=http_client,
        crawler=None,
    )

    # 진행률 UI 준비
    progress = Progress(
        SpinnerColumn(style="bold cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None, complete_style="green", finished_style="magenta"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
        auto_refresh=False,
    )
    progress_task = progress.add_task("🧭 스캔 준비 중", total=1)

    def on_progress(info: ProgressInfo):
        total = info.total or 1
        progress.update(
            progress_task,
            total=total,
            completed=info.current,
            description=info.message,
            refresh=True,
        )

    scanner = Scanner(
        config=config,
        scan_context=scan_ctx,
        auth_adapter=auth_adapter,
        auth_credentials=auth_credentials,
        logger=logger,
        on_progress=on_progress,
    )

    # Scan 실행 + Duration 계산
    with progress:
        start = datetime.utcnow()
        report = scanner.scan()
        end = datetime.utcnow()
        progress.update(
            progress_task, completed=progress.tasks[0].total, description="🏁 스캔 완료"
        )

  

    # Rich Summary (fail-safe for tests with minimal FakeScanReport)
    try:
        plugin_results = getattr(report, "plugin_results", []) or []
        target_url = getattr(report, "target_url", None) or request.target_url
        duration_seconds = getattr(report, "duration_seconds", None)
        if duration_seconds is None:
            start = getattr(report, "start_time", getattr(report, "started_at", None))
            end = getattr(report, "end_time", getattr(report, "finished_at", None))
            if start and end:
                duration_seconds = (end - start).total_seconds()
        duration_text = (
            f"{duration_seconds:.2f} seconds"
            if isinstance(duration_seconds, (int, float))
            else "-"
        )

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
        summary_table.add_row(
            "📄 Output Format", getattr(config.output_config, "format", "-")
        )

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

        console.print("\n")
        console.print(summary_table)
        if plugin_results:
            console.print(plugin_table)
        console.print("\n")
    except Exception as exc:  # pylint: disable=broad-except
        logger.debug("Failed to render summary tables: %s", exc)

    # Report 출력
    try:
        output_report(report, config.output_config)
        logger.info("Scan report successfully generated.")
    except Exception as exc:
        logger.exception("Failed to output report: %s", exc)


if __name__ == "__main__":
    cli()
