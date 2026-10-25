"""Scan engine — orchestrates file discovery and rule execution."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from .models import Finding, Language, ScanConfig, ScanResult, Severity
from .discovery import FileDiscovery
from .rules import scan_python_file, scan_js_file


class ScanEngine:
    """Main scanning engine that coordinates discovery and analysis."""

    def __init__(self, config: ScanConfig | None = None):
        self.config = config or ScanConfig()
        self.discovery = FileDiscovery(self.config)

    def scan(self, path: str) -> ScanResult:
        """Run a full scan on the given path."""
        start = time.time()
        start_iso = datetime.now(timezone.utc).isoformat()
        project_root = os.path.abspath(path)

        # Discover files
        files_by_lang = self.discovery.discover(path)

        findings: list[Finding] = []
        files_scanned = 0

        # Scan Python files
        for filepath in files_by_lang.get(Language.PYTHON, []):
            file_findings = scan_python_file(filepath, project_root)
            findings.extend(file_findings)
            files_scanned += 1

        # Scan JavaScript files
        for filepath in files_by_lang.get(Language.JAVASCRIPT, []):
            file_findings = scan_js_file(filepath, project_root)
            findings.extend(file_findings)
            files_scanned += 1

        # Apply suppressions
        suppressed_count = self._apply_suppressions(findings)

        # Filter by minimum severity
        active = [
            f for f in findings
            if not f.suppressed and f.severity.weight >= self.config.min_severity.weight
        ]

        duration = time.time() - start

        return ScanResult(
            project_path=project_root,
            scan_time=start_iso,
            files_scanned=files_scanned,
            findings=active,
            duration_seconds=duration,
            suppressed_count=suppressed_count,
        )

    def _apply_suppressions(self, findings: list[Finding]) -> int:
        """Apply suppression rules from config. Returns suppressed count."""
        if not self.config.suppressions:
            return 0

        suppressed = 0
        for finding in findings:
            key = finding.rule_id
            if key in self.config.suppressions:
                for supp in self.config.suppressions[key]:
                    # Check if suppression applies to this finding
                    supp_file = supp.get("file", "")
                    supp_lines = supp.get("lines", [])

                    if supp_file and supp_file != finding.file:
                        continue

                    if supp_lines and finding.line not in supp_lines:
                        continue

                    finding.suppressed = True
                    suppressed += 1
                    break

        return suppressed
