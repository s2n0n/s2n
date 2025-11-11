from __future__ import annotations
import click
import logging
from datetime import datetime
from dataclasses import asdict
from pathlib import Path    

from s2n.s2nscanner.interfaces import CLIArguments, ScanContext, Finding
from s2n.s2nscanner.cli.mapper import cliargs_to_scanrequest
from s2n.s2nscanner.cli.config_builder import build_scan_config
from s2n.s2nscanner.auth.dvwa_adapter import DVWAAdapter
from s2n.s2nscanner.scan_engine import Scanner

# logger 초기화
def init_logger(verbose: bool, log_file: str | None) -> logging.Logger:
    logger = logging.getLogger("s2n")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger

# CLI entrypoint
@click.group()
def cli():
    """S2N Web Vulnerability Scanner CLI"""
    pass

# Scan 명령어
@cli.command("scan")
@click.option("-u", "--url", required=True, help="스캔 대상 URL")
@click.option("-p", "--plugin", multiple=True, help="사용할 플러그인 이름 (복수 선택 가능)")
@click.option("-a", "--auth", help="인증 타입 (NONE, BASIC, BEARER, DVWA 등)")
@click.option("--username", help="인증용 사용자명")
@click.option("--password", help="인증용 비밀번호")
@click.option("-o", "--output", help="결과 출력 파일 경로 (예: result.json)")
@click.option("-v", "--verbose", is_flag=True, help="상세 로그 출력")
@click.option("--log-file", help="로그 파일 경로")
def scan(url, plugin, auth, username, password, output, verbose, log_file):
    logger = init_logger(verbose, log_file)
    logger.info("Starting scan for %s", url)

    # CLIArguments  구성
    args = CLIArguments(
        url=url,
        plugin=list(plugin),
        auth=auth,
        username=username,
        password=password,
        output=output,
        verbose=verbose,
        log_file=log_file,
    )

    # ScanRequest 변환
    request = cliargs_to_scanrequest(args)

    # ScanConfig 구성
    config = build_scan_config(request)

    # 인증/세션 생성
    http_client = None
    auth_adapter = None
    if request.auth_type:
        if request.auth_type.name.lower() == "dvwa":
            logger.info("DVWA authentication requested.")
            adapter = DVWAAdapter(base_url=request.target_url)
            ok = adapter.ensure_authenticated(
                [(request.username or "admin", request.password or "password")]
            )
            if ok:
                http_client = adapter.get_client()
                auth_adapter = adapter
                logger.info("DVWA 로그인 완료")
            else:
                logger.warning("DVWA 로그인 실패 - 인증 없는 세션으로 계속 진행")

    # ScanContext 생성
    scan_ctx = ScanContext(
        scan_id=f"scan-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        start_time=datetime.utcnow(),
        config=config,
        http_client=http_client,
        crawler=None,
    )

    # Scanner 실행
    scanner = Scanner(config=config, scan_context=scan_ctx, auth_adapter=auth_adapter, logger=logger)
    report = scanner.scan()

    ## 추후 report.py 머지 후 삭제 예정
    # 결과 출력
    if verbose:
        click.echo("\n===== Scan Summary =====")
        click.echo(f"Target: {report.target_url}")
        click.echo(f"Total Vulnerabilities: {report.summary.total_vulnerabilities}")
        for sev, count in report.summary.severity_counts.items():
            click.echo(f" - {sev}: {count}")
        click.echo("========================\n")
    else:
        click.echo(f"[+] Scan finished for {report.target_url}")
        click.echo(f"→ Vulnerabilities: {report.summary.total_vulnerabilities}")

    # 결과 저장
    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            from json import dump
            dump(asdict(report), f, indent=2, ensure_ascii=False)
        logger.info("Saved report to %s", output_path)


if __name__ == "__main__":
    cli()