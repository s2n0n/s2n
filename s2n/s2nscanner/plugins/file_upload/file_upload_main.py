import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import os
import re
import tempfile
import uuid
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

# interfaces에서 제공되는 타입 사용
from s2n.s2nscanner.interfaces import (
    Finding,
    PluginContext,
    PluginError,
    PluginResult,
    PluginStatus,
    Severity,
)
	
# 헬퍼 함수 임포트: 패키지 실행/모듈 실행/직접 실행 모두 지원
try:
    from .file_upload_utils import collect_form_data, find_login_form, find_upload_form, guess_uploaded_urls
except ImportError:
    from file_upload_utils import collect_form_data, find_login_form, find_upload_form, guess_uploaded_urls

logger = logging.getLogger("s2n.plugins.file_upload")


class FileUploadPlugin:
    name = "file_upload"
    description = "파일 업로드 취약점을 탐지합니다."

    def __init__(self, config: PluginContext | None = None):
        self.config = config or {}
        self.plugin_context = self.config or {}

    # TODO : 재귀 탐색 적용 (DFS 추후 PluginConfig에 깊이 설정 추가)
    def _dfs_find_form(self, url: str, session, visited: set, base_netloc: str, stats: Dict[str, int], depth: int, max_depth: int):
        """DFS 방식으로 링크를 재귀적으로 탐색하여 업로드 폼을 찾습니다."""
        if url in visited or depth > max_depth:
            return None, None, None

        logger.info(f"DFS 탐색 중 (depth={depth}): {url}")
        visited.add(url)
        stats['urls_scanned'] += 1

        try:
            resp = session.get(url, timeout=10)
            stats['requests_sent'] += 1
            soup = BeautifulSoup(resp.text, "html.parser")

            # 현재 페이지에서 폼 찾기
            form = find_upload_form(soup)
            if form:
                logger.info(f"DFS를 통해 업로드 폼 발견: {url}")
                return form, soup, url

            # 하위 링크로 재귀 호출
            for a_tag in soup.find_all("a", href=True):
                next_url_str = a_tag.get("href")
                if not next_url_str or str(next_url_str).startswith(('javascript:', 'mailto:')):
                    continue

                next_url = urljoin(url, str(next_url_str))
                if urlparse(next_url).netloc == base_netloc:
                    found_form, found_soup, found_url = self._dfs_find_form(next_url, session, visited, base_netloc, stats, depth + 1, max_depth)
                    if found_form:
                        return found_form, found_soup, found_url

        except Exception as e:
            logger.warning(f"DFS 탐색 중 에러 발생 ({url}): {e}")

        return None, None, None

    def run(self, plugin_context: PluginContext) -> PluginResult | PluginError:
        start_time = datetime.now()
        findings: List[Finding] = []
        stats = {'requests_sent': 0, 'urls_scanned': 0}
        target_url = plugin_context.scan_context.config.target_url
        session = plugin_context.scan_context.http_client

        test_path = None
        try:
            logger.info(f"[*] Fetching upload page: {target_url}")
            resp = session.get(target_url, timeout=10)
            stats['requests_sent'] += 1
            stats['urls_scanned'] += 1

            soup = BeautifulSoup(resp.text, "html.parser")
            form = find_upload_form(soup)
            found_at = target_url

            if form is None:
                login_form = find_login_form(soup)
                if login_form is not None:
                    logger.info("Login form found, but no upload form. Skipping.")
                    # 로그인 페이지로 판단됨 — 로그인 없이 이 페이지에서 업로드 폼이 없으므로 취약점 없음으로 간주
                    return PluginResult(
                        plugin_name=self.name, status=PluginStatus.SKIPPED, start_time=start_time,
                        end_time=datetime.now(), duration_seconds=(datetime.now() - start_time).total_seconds()
                    )

            # 현재 페이지에 폼이 없으면 DFS 탐색 시작
            if form is None:
                logger.info("현재 페이지에 업로드 폼이 없습니다. DFS 탐색을 시작합니다.")
                visited = {target_url}
                base_netloc = urlparse(target_url).netloc
                max_depth = plugin_context.scan_context.config.scanner_config.crawl_depth
                form, soup, found_at = self._dfs_find_form(target_url, session, visited, base_netloc, stats, depth=0, max_depth=max_depth)

            if form is None:
                logger.info("No upload form found on the page.")
                return PluginResult(
                    plugin_name=self.name, status=PluginStatus.SUCCESS, findings=findings,
                    start_time=start_time, end_time=datetime.now(),
                    duration_seconds=(datetime.now() - start_time).total_seconds(),
                    urls_scanned=stats['urls_scanned'], requests_sent=stats['requests_sent']
                )

            action = form.get("action") or found_at
            action_url = urljoin(str(found_at), str(action))
            method = str((form.get("method") or "post")).lower()

            if method != "post":
                logger.warning(f"Form method is not POST (method={method}). Skipping.")
                return PluginResult(
                    plugin_name=self.name, status=PluginStatus.SKIPPED, start_time=start_time,
                    end_time=datetime.now(), duration_seconds=(datetime.now() - start_time).total_seconds()
                )

            data = collect_form_data(form)
            file_input = form.find("input", {"type": "file"})
            file_field_name = str(file_input.get("name"))  or "file" if file_input else "file"

            if( not file_input or not file_field_name):
                logger.info("No file input field found in the upload form.")
                return PluginResult(
                    plugin_name=self.name, status=PluginStatus.SUCCESS, findings=findings,
                    start_time=start_time, end_time=datetime.now(),
                    duration_seconds=(datetime.now() - start_time).total_seconds(),
                    urls_scanned=stats['urls_scanned'], requests_sent=stats['requests_sent']
                )

            test_content = '<?php echo "File Upload Test"; ?>'
            tmp_dir = tempfile.gettempdir()
            filename = f"test_upload_{uuid.uuid4().hex}.php"
            test_path = os.path.join(tmp_dir, filename)
            with open(test_path, "w", encoding="utf-8") as f:
                f.write(test_content)
            
            with open(test_path, "rb") as fobj:
                files = {file_field_name: (filename, fobj, "application/x-php")}
                # TODO 나중에 위험할 수 있다 - DVWA 아니면 위험하게 사용될 수도 있다.
                response = session.post(action_url, data=data, files=files, timeout=15)
                stats['requests_sent'] += 1
            
            # TODO : GET으로 Severity.HIGH 판단하는 방법? (DVWA 기준)
            candidates = guess_uploaded_urls(response, action_url)
            # TODO 더 정교한 후보 필터링 로직 가능할 것 같다. + 병렬처리해도 될 듯
            for url in candidates:
                try:
                    r = session.get(url, timeout=10)
                    stats['requests_sent'] += 1
                    if r.status_code == 200:
                        findings.append( Finding(
                            id=f"file-upload-{uuid.uuid4()}",
                            plugin=self.name,
                            severity=Severity.HIGH,
                            title="File Upload Vulnerability Detected",
                            description=f"Arbitrary file upload seems possible. A test file was uploaded and is accessible at {url}.",
                            url=url,
                            evidence=f"Test file content found at {url}",
                            timestamp=datetime.now(),
                        ))
                        # 하나의 취약점을 찾으면 중단
                        break
                except Exception:
                    continue

            if not findings and re.search(
                # TODO: 더 많은 성공 패턴 추가 가능
                r"successfully uploaded|file uploaded|upload complete|uploaded successfully",
                response.text,
                flags=re.I,
            ):
                findings.append(Finding(
                    id=f"file-upload-potential-{uuid.uuid4()}",
                    plugin=self.name,
                    severity=Severity.MEDIUM,
                    title="Potential File Upload Vulnerability",
                    description="Server reported a successful upload, but the file's location could not be determined.",
                    url=action_url,
                    evidence=response.text[:500],
                    timestamp=datetime.now(),
                ))
                
        except Exception as e:
            logger.exception(f"[!] Error during file upload testing: {e}")
            return PluginError(
                error_type=type(e).__name__,
                message=str(e),
                traceback=str(e.__traceback__)
            )


        # if test_path and os.path.exists(test_path):
        #         try:
        #             os.remove(test_path)
        #             logger.info(f"[*] Removed temp file: {test_path}")
        #         except Exception as e:
        #             logger.warning(f"[!] Warning: could not remove temp file: {e}")

        return PluginResult(
            plugin_name=self.name,
            status=PluginStatus.SUCCESS,
            findings=findings,
            start_time=start_time,
            end_time=datetime.now(),
            duration_seconds=(datetime.now() - start_time).total_seconds(),
            # TODO : 실제 스캔된 URL 수와 요청 수로 변경
            urls_scanned=int(stats['urls_scanned']),
            requests_sent=stats['requests_sent']
        )


def main(config : PluginContext | None=None ):
    """플러그인 인스턴스를 생성하여 반환합니다."""
    return FileUploadPlugin(config)