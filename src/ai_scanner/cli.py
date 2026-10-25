"""CLI entry point for the AI Code Security Scanner."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .engine import ScanEngine
from .models import Language, ScanConfig, Severity
from .reporters import render_json, render_markdown, render_sarif, render_terminal
from .rules import get_python_rules, get_js_rules

app = typer.Typer(
    name="ai-code-security-scanner",
    help="Find security risks in Python and JavaScript code. Understand the findings. Fix them.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    path: str = typer.Argument(..., help="Path to scan (file or directory)"),
    format: str = typer.Option(
        "terminal",
        "--format", "-f",
        help="Output format: terminal, json, markdown, sarif",
    ),
    output: str = typer.Option(
        None,
        "--output", "-o",
        help="Write report to file instead of stdout",
    ),
    min_severity: str = typer.Option(
        "LOW",
        "--min-severity",
        help="Minimum severity: CRITICAL, HIGH, MEDIUM, LOW, INFO",
    ),
    language: list[str] = typer.Option(
        None,
        "--language", "-l",
        help="Restrict to specific languages (python, javascript). Can be repeated.",
    ),
    exclude: list[str] = typer.Option(
        None,
        "--exclude",
        help="Additional directory patterns to exclude. Can be repeated.",
    ),
    config_file: str = typer.Option(
        None,
        "--config",
        help="Path to YAML config file with suppression rules",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress non-essential output"),
):
    """Scan Python and JavaScript files for security vulnerabilities."""
    # Build config
    config = ScanConfig(path=path)

    # Parse minimum severity
    try:
        config.min_severity = Severity(min_severity.upper())
    except ValueError:
        console.print(f"[red]Invalid severity: {min_severity}. Use CRITICAL, HIGH, MEDIUM, LOW, or INFO.[/red]")
        raise typer.Exit(code=2)

    # Parse languages
    if language:
        config.languages = []
        for lang in language:
            lang_lower = lang.lower()
            if lang_lower in ("python", "py"):
                config.languages.append(Language.PYTHON)
            elif lang_lower in ("javascript", "js"):
                config.languages.append(Language.JAVASCRIPT)
            else:
                console.print(f"[red]Unknown language: {lang}. Use 'python' or 'javascript'.[/red]")
                raise typer.Exit(code=2)

    # Additional exclusions
    if exclude:
        config.exclude_dirs.extend(exclude)

    # Load suppression config
    if config_file:
        config = _load_config_file(config_file, config)

    # Run scan
    engine = ScanEngine(config)
    result = engine.scan(path)

    # Render output
    fmt = format.lower()
    if fmt == "terminal":
        output_text = render_terminal(result, console)
    elif fmt == "json":
        output_text = render_json(result)
    elif fmt == "markdown":
        output_text = render_markdown(result)
    elif fmt == "sarif":
        output_text = render_sarif(result)
    else:
        console.print(f"[red]Unknown format: {format}. Use terminal, json, markdown, or sarif.[/red]")
        raise typer.Exit(code=2)

    # Write to file or stdout
    if output:
        Path(output).write_text(output_text, encoding="utf-8")
        console.print(f"[green]Report written to {output}[/green]")
    elif fmt != "terminal":
        print(output_text)

    # Exit code based on findings
    if result.critical_count > 0:
        raise typer.Exit(code=3)
    elif result.high_count > 0:
        raise typer.Exit(code=2)
    elif result.medium_count > 0:
        raise typer.Exit(code=1)


@app.command()
def rules(
    language: str = typer.Option(
        None, "--language", "-l", help="Filter rules by language (python, javascript)"
    ),
    detail: bool = typer.Option(False, "--detail", "-d", help="Show full rule details"),
):
    """List all available security rules."""
    table = Table(title="Security Rules", show_header=True, header_style="bold cyan")
    table.add_column("Rule ID", style="cyan", no_wrap=True)
    table.add_column("Language", no_wrap=True)
    table.add_column("Title", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Confidence", no_wrap=True)
    table.add_column("Category", no_wrap=True)

    all_rules = []
    py_rules = get_python_rules()
    js_rules = get_js_rules()

    if language is None or language.lower() in ("python", "py"):
        all_rules.extend(("Python", r) for r in py_rules)
    if language is None or language.lower() in ("javascript", "js"):
        all_rules.extend(("JavaScript", r) for r in js_rules)

    for lang_name, rule in all_rules:
        sev_color = {
            Severity.CRITICAL: "red bold",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }.get(rule.severity, "white")
        table.add_row(
            rule.rule_id,
            lang_name,
            rule.title,
            f"[{sev_color}]{rule.severity.value}[/{sev_color}]",
            rule.confidence.value,
            rule.category,
        )

    console.print(table)

    if detail:
        for lang_name, rule in all_rules:
            console.print(f"\n[bold cyan]{rule.rule_id}: {rule.title}[/bold cyan]")
            console.print(f"  Language: {lang_name}")
            console.print(f"  Severity: {rule.severity.value}")
            console.print(f"  Confidence: {rule.confidence.value}")
            console.print(f"  Category: {rule.category}")
            console.print(f"  Description: {rule.description}")
            console.print(f"  Impact: {rule.impact}")
            console.print(f"  Remediation: {rule.remediation}")
            if rule.references:
                console.print("  References:")
                for ref in rule.references:
                    console.print(f"    - {ref}")


@app.command()
def version():
    """Show the scanner version."""
    console.print(f"ai-code-security-scanner v{__version__}")


def _load_config_file(config_path: str, base_config: ScanConfig) -> ScanConfig:
    """Load suppression config from a YAML file."""
    try:
        import yaml
    except ImportError:
        console.print("[red]PyYAML is required for config files. Install with: pip install pyyaml[/red]")
        raise typer.Exit(code=2)

    try:
        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            return base_config

        # Apply suppressions
        suppressions = data.get("suppressions", {})
        for rule_id, supp_list in suppressions.items():
            if rule_id not in base_config.suppressions:
                base_config.suppressions[rule_id] = []
            base_config.suppressions[rule_id].extend(supp_list)

        # Apply exclude_dirs
        exclude_dirs = data.get("exclude_dirs", [])
        if exclude_dirs:
            base_config.exclude_dirs.extend(exclude_dirs)

        return base_config

    except FileNotFoundError:
        console.print(f"[red]Config file not found: {config_path}[/red]")
        raise typer.Exit(code=2)
    except yaml.YAMLError as e:
        console.print(f"[red]Invalid YAML in config file: {e}[/red]")
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
