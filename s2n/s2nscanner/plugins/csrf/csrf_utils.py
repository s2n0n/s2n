from html.parser import HTMLParser
from typing import List, Dict


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._in_form = False
        self._current = None

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attrs_dict = {k.lower(): v for k, v in attrs}
        if tag == "form":
            self._in_form = True
            self._current = {"attrs": attrs_dict, "inputs": [], "html": ""}
            attr_text = " ".join(f'{k}="{v}"' for k, v in attrs)
            self._current["html"] += f"<form {attr_text}>"
            return

        if self._in_form and self._current is not None:
            if tag == "input":
                self._current["inputs"].append(attrs_dict)
            attr_text = " ".join(f'{k}="{v}"' for k, v in attrs)
            self._current["html"] += f"<{tag} {attr_text}>"

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self._in_form and self._current is not None:
            self._current["html"] += f"</{tag}>"
        if tag == "form" and self._in_form:
            if self._current is not None:
                self.forms.append(self._current)
            self._current = None
            self._in_form = False

    def handle_data(self, data):
        if self._in_form and self._current is not None:
            self._current["html"] += data


class MetaTokenParser(HTMLParser):
    """Parse <meta> tags and extract CSRF token attributes."""

    def __init__(self, token_names: tuple):
        super().__init__()
        self._token_names = tuple(n.lower() for n in token_names)
        self.tokens: List[Dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list):
        if tag.lower() != "meta":
            return
        attrs_dict = {k.lower(): (v or "") for k, v in attrs}
        name = attrs_dict.get("name", "").lower()
        if name and any(tn in name for tn in self._token_names):
            self.tokens.append({
                "name": attrs_dict.get("name", ""),
                "content": attrs_dict.get("content", ""),
            })