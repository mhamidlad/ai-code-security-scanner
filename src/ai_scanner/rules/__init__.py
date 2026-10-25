"""Rules package — Python and JavaScript detection rules."""

from .python_rules import scan_python_file, get_python_rules, PythonRule, RULES as PY_RULES
from .javascript_rules import scan_js_file, get_js_rules, JSRule, RULES as JS_RULES

__all__ = [
    "scan_python_file",
    "get_python_rules",
    "PythonRule",
    "PY_RULES",
    "scan_js_file",
    "get_js_rules",
    "JSRule",
    "JS_RULES",
]
