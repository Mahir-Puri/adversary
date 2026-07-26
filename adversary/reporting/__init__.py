"""Render run results as terminal output, JSON, and a standalone HTML report."""

from .console import render_console
from .json_report import render_json
from .html_report import render_html

__all__ = ["render_console", "render_json", "render_html"]
