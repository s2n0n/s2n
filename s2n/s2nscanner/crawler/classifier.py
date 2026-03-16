"""
PageClassifier — HTML 폼 자동 분류 모듈
- 페이지 내 폼을 분석해 LOGIN, TEXT_INPUT, FILE_UPLOAD, COMMAND, SEARCH, GENERIC 등으로 분류
- 재사용: helper.py의 Form/FormParser, csrf_constants.py의 CSRF_TOKEN_KEYWORDS 등
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from s2n.s2nscanner.plugins.helper import Form, FormParser
from s2n.s2nscanner.plugins.csrf.csrf_constants import (
    CSRF_TOKEN_KEYWORDS,
    META_CSRF_NAMES,
    JS_TOKEN_PATTERN,
)
from s2n.s2nscanner.logger import get_logger

logger = get_logger("classifier")


# ============================================================================
# 데이터 구조
# ============================================================================

class FormType(str, Enum):
    LOGIN = "LOGIN"
    TEXT_INPUT = "TEXT_INPUT"
    FILE_UPLOAD = "FILE_UPLOAD"
    COMMAND = "COMMAND"
    SEARCH = "SEARCH"
    GENERIC = "GENERIC"


@dataclass
class FieldInfo:
    name: str
    field_type: str           # text, password, hidden, file, email, textarea 등
    value: str                # 기본값
    is_csrf_token: bool       # CSRF 토큰 여부


@dataclass
class ClassifiedForm:
    form: Form                          # helper.py의 Form 재사용
    form_type: FormType
    url: str                            # 발견된 페이지 URL
    action_url: str                     # 폼 action (절대 URL)
    method: str                         # GET/POST
    fields: Dict[str, FieldInfo] = field(default_factory=dict)
    csrf_token: Optional[Dict[str, str]] = None   # {name, value}
    score: float = 0.0                  # 분류 확신도


@dataclass
class PageInfo:
    url: str
    forms: List[ClassifiedForm] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    has_login_form: bool = False
    has_attack_surface: bool = False
    params: List[str] = field(default_factory=list)  # URL 쿼리 파라미터


# ============================================================================
# 분류기
# ============================================================================

# 커맨드 인젝션 힌트 키워드
_COMMAND_KEYWORDS = {"cmd", "command", "exec", "ping", "ip", "host", "shell", "run"}
# 검색 힌트 키워드
_SEARCH_KEYWORDS = {"search", "query", "q", "keyword", "find", "s", "term"}


class PageClassifier:
    """HTML 페이지를 분석해 폼을 자동 분류하는 핵심 클래스."""

    def classify_page(self, url: str, html: str) -> PageInfo:
        """페이지 전체를 분석해 PageInfo 반환."""
        # 폼 파싱
        parser = FormParser()
        parser.feed(html)

        classified_forms: List[ClassifiedForm] = []
        for form in parser.forms:
            cf = self.classify_form(form, url, html)
            classified_forms.append(cf)

        # 링크 추출 (a href)
        links: List[str] = []
        for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\']', html, re.I):
            href = m.group(1)
            if href.startswith(("mailto:", "javascript:")):
                continue
            full = urllib.parse.urljoin(url, href)
            links.append(full)

        # URL 쿼리 파라미터
        parsed = urllib.parse.urlparse(url)
        params = [k for k, _ in urllib.parse.parse_qsl(parsed.query)]

        has_login = any(cf.form_type == FormType.LOGIN for cf in classified_forms)
        has_attack = (
            any(cf.form_type != FormType.LOGIN for cf in classified_forms)
            or len(params) > 0
        )

        return PageInfo(
            url=url,
            forms=classified_forms,
            links=links,
            has_login_form=has_login,
            has_attack_surface=has_attack,
            params=params,
        )

    def classify_form(self, form: Form, url: str, html: str) -> ClassifiedForm:
        """개별 폼을 분류해 ClassifiedForm 반환."""
        form_type, score = self._detect_form_type(form)
        action_raw = form.get("action", "")
        action_url = urllib.parse.urljoin(url, action_raw) if action_raw else url
        method = (form.get("method") or "GET").upper()

        fields: Dict[str, FieldInfo] = {}
        for inp in form.inputs:
            fi = self._detect_field_info(inp)
            if fi.name:
                fields[fi.name] = fi

        csrf_token = self._extract_csrf_token(form, html)

        return ClassifiedForm(
            form=form,
            form_type=form_type,
            url=url,
            action_url=action_url,
            method=method,
            fields=fields,
            csrf_token=csrf_token,
            score=score,
        )

    # ------------------------------------------------------------------
    # 내부 메서드
    # ------------------------------------------------------------------

    def _detect_form_type(self, form: Form) -> Tuple[FormType, float]:
        """폼 inputs를 분석해 FormType과 확신도(score)를 반환."""
        has_password = False
        has_file = False
        has_command_hint = False
        has_search_hint = False
        has_text_input = False

        action = (form.get("action") or "").lower()

        for inp in form.inputs:
            inp_type = (inp.get("type") or "text").lower()
            inp_name = (inp.get("name") or "").lower()

            if inp_type == "password":
                has_password = True
            elif inp_type == "file":
                has_file = True
            elif inp_type in ("text", "email", "url", "number", "tel"):
                has_text_input = True
                if inp_name in _COMMAND_KEYWORDS:
                    has_command_hint = True
                if inp_name in _SEARCH_KEYWORDS:
                    has_search_hint = True
            elif inp_type == "textarea" or inp.get("tag") == "textarea":
                has_text_input = True
                if inp_name in _COMMAND_KEYWORDS:
                    has_command_hint = True

        # textarea는 <textarea> 태그로 올 수도 있어 FormParser가 input으로 잡지 못할 수 있음
        # action URL에 search 키워드가 있으면 search 힌트
        if "search" in action:
            has_search_hint = True

        # 우선순위 기반 분류
        if has_password:
            return FormType.LOGIN, 0.95
        if has_file:
            return FormType.FILE_UPLOAD, 0.90
        if has_command_hint:
            return FormType.COMMAND, 0.85
        if has_search_hint:
            return FormType.SEARCH, 0.80
        if has_text_input:
            return FormType.TEXT_INPUT, 0.70
        return FormType.GENERIC, 0.50

    def _extract_csrf_token(self, form: Form, html: str) -> Optional[Dict[str, str]]:
        """폼 내 hidden input 또는 meta/JS에서 CSRF 토큰을 추출."""
        # 1) 폼 내 hidden input에서 탐지
        for inp in form.inputs:
            inp_type = (inp.get("type") or "").lower()
            inp_name = (inp.get("name") or "").lower()
            if inp_type == "hidden" and inp_name:
                for kw in CSRF_TOKEN_KEYWORDS:
                    if kw in inp_name:
                        return {"name": inp.get("name", ""), "value": inp.get("value", "")}

        # 2) <meta> 태그에서 탐지
        for meta_name in META_CSRF_NAMES:
            pattern = rf'<meta[^>]+name=["\']?{re.escape(meta_name)}["\']?[^>]+content=["\']([^"\']+)["\']'
            m = re.search(pattern, html, re.I)
            if m:
                return {"name": meta_name, "value": m.group(1)}

        # 3) JS 변수에서 탐지
        m = re.search(JS_TOKEN_PATTERN, html, re.I)
        if m:
            return {"name": "js_csrf_token", "value": m.group(1)}

        return None

    def _detect_field_info(self, input_attrs: Dict[str, str]) -> FieldInfo:
        """input 속성 dict → FieldInfo."""
        name = input_attrs.get("name", "")
        field_type = (input_attrs.get("type") or "text").lower()
        value = input_attrs.get("value", "")

        is_csrf = False
        if field_type == "hidden" and name:
            name_lower = name.lower()
            for kw in CSRF_TOKEN_KEYWORDS:
                if kw in name_lower:
                    is_csrf = True
                    break

        return FieldInfo(
            name=name,
            field_type=field_type,
            value=value,
            is_csrf_token=is_csrf,
        )
