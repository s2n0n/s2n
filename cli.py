# CLI 실행용
# CLI 실행용
from __future__ import annotations
import sys
import json
import logging
import importlib
from typing import List, Optional, Dict, Any
import click 
from s2n.s2nscanner.scan_engine import Scanner, ScanReport

# config loader
def load_config(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    try:
        if path.endswith(".json"):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
            # toml/yaml support 확장 가능 (mvp에서는 제외)

        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise click.ClickException(f"Failed to load config {path}: {e}")
    

# def init_logger(verbose: bool, log_file: Optional[str]) -> logging.Logger: