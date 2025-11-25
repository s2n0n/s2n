import re
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser
from typing import List, Dict, Any, Optional


class Form:
    def __init__(self, attrs: Dict[str, str]):
        self.attrs = attrs
        self.inputs: List[Dict[str, str]] = []

    def get(self, key: str, default: Any = None) -> Any:
        return self.attrs.get(key, default)


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: List[Form] = []
        self.current_form: Optional[Form] = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "form":
            self.current_form = Form(attrs_dict)
        elif tag == "input" and self.current_form is not None:
            self.current_form.inputs.append(attrs_dict)

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


def find_upload_form(content: str) -> Optional[Form]:
    """HTML에서 파일 업로드 폼을 찾습니다."""
    parser = FormParser()
    parser.feed(content)

    for form in parser.forms:
        if any(inp.get("type") == "file" for inp in form.inputs):
            return form
    return None


def find_login_form(content: str) -> Optional[Form]:
    """HTML에서 로그인 폼으로 보이는 것을 찾습니다."""
    parser = FormParser()
    parser.feed(content)

    for form in parser.forms:
        if any(inp.get("type") == "password" for inp in form.inputs):
            action = str(form.get("action", "")).lower()
            if "login" in action or "signin" in action:
                return form
    return None


def collect_form_data(form: Form) -> dict:
    """폼에서 모든 입력 필드(hidden 포함)의 데이터를 수집합니다."""
    data = {}
    for input_attrs in form.inputs:
        name = input_attrs.get("name")
        value = input_attrs.get("value", "")
        # type이 submit, button, reset이 아닌 경우에만 추가
        if name and input_attrs.get("type") not in ["submit", "button", "reset"]:
            data[name] = value
    return data


def guess_uploaded_urls(response, base_url: str) -> list[str]:
    """업로드 성공 후 파일이 있을 만한 URL들을 추측합니다."""
    urls = set()

    # 1. 응답 본문에서 링크 찾기
    hrefs = re.findall(r'<a\s+(?:[^>]*?\s+)?href=(["\'])(.*?)\1', response.text, re.I)
    for _, href in hrefs:
        full_url = urljoin(base_url, str(href))
        urls.add(full_url)

    # 2. 일반적인 업로드 경로 추측
    parsed_base = urlparse(base_url)
    filename = "test.php"  # A common test filename
    common_paths = ["uploads/", "files/", "images/", "./"]
    for path in common_paths:
        # action URL 기준
        guess = urljoin(base_url, path + filename)
        urls.add(guess)
        # 루트 기준
        root_guess = f"{parsed_base.scheme}://{parsed_base.netloc}/{path}{filename}"
        urls.add(root_guess)

    # 3. 응답 텍스트에서 URL 같은 문자열 찾기
    found_in_text = re.findall(r'["\'](/[^"\\]+)["\']', response.text)
    for path in found_in_text:
        if path.endswith(
            (".php", ".jpg", ".png", ".txt")
        ):  # Add more extensions if needed
            urls.add(urljoin(base_url, path))

    return list(urls)


def perform_login(session, login_url: str, form: Form, credentials: dict):
    """(미사용) 로그인 폼에 데이터를 전송하여 로그인을 시도합니다."""
    data = collect_form_data(form)
    # credentials 딕셔너리로 사용자 이름과 비밀번호 필드를 채웁니다.
    # 'username', 'password' 필드 이름을 찾아야 함
    username_field = "username"  # This might need to be smarter
    password_field = "password"
    data[username_field] = credentials.get("username")
    data[password_field] = credentials.get("password")

    try:
        response = session.post(login_url, data=data)
        return "logout" in response.text.lower()  # 로그인 성공 여부 판단
    except Exception:
        return False
