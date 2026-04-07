from s2n.s2nscanner.interfaces import PluginContext
from s2n.s2nscanner.clients.http_client import HttpClient

from typing import Any, ClassVar, Dict, List, Optional
from html.parser import HTMLParser

def resolve_client(self: ClassVar, plugin_context: PluginContext) -> HttpClient:
    scan_ctx = getattr(plugin_context, "scan_context", None)

    # auth_adapter가 제공되면 해당 세션을 우선 사용
    adapter = getattr(scan_ctx, "auth_adapter", None)
    if adapter and hasattr(adapter, "get_client"):
        return adapter.get_client()

    http_client = getattr(scan_ctx, "http_client", None)
    if http_client:
        return http_client

    # fallback: initialize에서 받은 http 또는 새 HttpClient
    if getattr(self, "http", None):
        return self.http

    return HttpClient()

def resolve_depth(self: ClassVar, plugin_context: PluginContext) -> int:
    depth = self.depth
    plugin_cfg = getattr(plugin_context, "plugin_config", None)
    if plugin_cfg and getattr(plugin_cfg, "custom_params", None):
        depth = int(plugin_cfg.custom_params.get("depth", depth))
    return depth

def resolve_target_url(self: ClassVar, plugin_context: PluginContext) -> str:
    scan_ctx = getattr(plugin_context, "scan_context", None)
    if scan_ctx:
        config = getattr(scan_ctx, "config", None)
        if config and getattr(config, "target_url", None):
            return config.target_url.rstrip("/")

        target_url = getattr(scan_ctx, "target_url", None)
        if target_url:
            return str(target_url).rstrip("/")

    raise ValueError("ScanContext에 target_url 정보가 없습니다.")
    

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