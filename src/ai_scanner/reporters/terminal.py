"""Terminal reporter — Rich-formatted console output."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from ..models import ScanResult, Severity


def _severity_color(severity: Severity) -> str:
    colors = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }
    return colors.get(severity, "white")


def render_terminal(result: ScanResult, console: Console | None = None) -> str:
    """Render scan results to the terminal using Rich.

    Returns a plain-text representation for testing purposes.
    """
    console = console or Console()
    lines: list[str] = []

    # Header
    header = Panel(
        Text("AI Code Security Scanner", style="bold cyan"),
        subtitle=f"v{result.scanner_version}",
    )
    console.print(header)
    lines.append("AI Code Security Scanner")
    lines.append(f"v{result.scanner_version}")
    lines.append("")

    # Summary
    summary_table = Table(title="Scan Summary", show_header=True)
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Project", result.project_path)
    summary_table.add_row("Files scanned", str(result.files_scanned))
    summary_table.add_row("Scan time", result.scan_time)
    summary_table.add_row("Duration", f"{result.duration_seconds:.3f}s")
    summary_table.add_row("Total findings", str(len(result.active_findings)))
    summary_table.add_row("Critical", str(result.critical_count), style="red bold")
    summary_table.add_row("High", str(result.high_count), style="red")
    summary_table.add_row("Medium", str(result.medium_count), style="yellow")
    summary_table.add_row("Low", str(result.low_count), style="blue")
    summary_table.add_row("Info", str(result.info_count), style="dim")

    console.print(summary_table)

    lines.append(f"Project: {result.project_path}")
    lines.append(f"Files scanned: {result.files_scanned}")
    lines.append(f"Total findings: {len(result.active_findings)}")
    lines.append(f"  Critical: {result.critical_count}")
    lines.append(f"  High: {result.high_count}")
    lines.append(f"  Medium: {result.medium_count}")
    lines.append(f"  Low: {result.low_count}")
    lines.append(f"  Info: {result.info_count}")
    lines.append("")

    # Findings
    if result.active_findings:
        findings_table = Table(title="Findings", show_header=True)
        findings_table.add_column("#", style="dim", width=4)
        findings_table.add_column("Severity", width=10)
        findings_table.add_column("Rule", style="cyan", width=8)
        findings_table.add_column("File", style="white")
        findings_table.add_column("Line", style="dim", width=6)
        findings_table.add_column("Category", width=20)
        findings_table.add_column("Description", width=60)

        for idx, finding in enumerate(result.active_findings, 1):
            sev_color = _severity_color(finding.severity)
            findings_table.add_row(
                str(idx),
                Text(finding.severity.value, style=sev_color),
                finding.rule_id,
                finding.file,
                str(finding.line),
                finding.category,
                finding.description[:80] + "..." if len(finding.description) > 80 else finding.description,
            )

        console.print(findings_table)

        for idx, finding in enumerate(result.active_findings, 1):
            panel = Panel(
                Text.assemble(
                    (f"[{finding.severity.value}] ", sev_color),
                    (f"{finding.rule_id}: {finding.title}\n\n", "bold"),
                    (f"File: {finding.file}:{finding.line}\n", "white"),
                    (f"Language: {finding.language.value}\n\n", "dim"),
                    ("Description:\n", "bold"),
                    (f"{finding.description}\n\n", "white"),
                    ("Evidence:\n", "bold"),
                    (f"{finding.evidence}\n\n", "yellow"),
                    ("Impact:\n", "bold"),
                    (f"{finding.impact}\n\n", "red"),
                    ("Remediation:\n", "bold"),
                    (f"{finding.remediation}\n\n", "green"),
                    ("References:\n", "bold"),
                    ("\n".join(f"  - {ref}" for ref in finding.references) + "\n", "blue"),
                    ("\nManual verification required: " + ("Yes" if finding.manual_verification_required else "No"), "dim"),
                ),
                title=f"Finding #{idx}",
                border_style=sev_color,
            )
            console.print(panel)

            lines.append(f"Finding #{idx}: [{finding.severity.value}] {finding.rule_id}: {finding.title}")
            lines.append(f"  File: {finding.file}:{finding.line}")
            lines.append(f"  Language: {finding.language.value}")
            lines.append(f"  Description: {finding.description}")
            lines.append(f"  Evidence: {finding.evidence}")
            lines.append(f"  Impact: {finding.impact}")
            lines.append(f"  Remediation: {finding.remediation}")
            if finding.references:
                lines.append("  References:")
                for ref in finding.references:
                    lines.append(f"    - {ref}")
            lines.append("")
    else:
        console.print("[green]No security findings detected.[/green]")
        lines.append("No security findings detected.")

    if result.suppressed_count > 0:
        console.print(f"[dim]{result.suppressed_count} finding(s) suppressed.[/dim]")
        lines.append(f"{result.suppressed_count} finding(s) suppressed.")

    return "\n".join(lines)
