"""File discovery — find and filter source files for scanning."""

from __future__ import annotations

import os
from pathlib import Path

from .models import Language, ScanConfig

# File extension to language mapping
EXTENSION_MAP: dict[str, Language] = {
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".ts": Language.JAVASCRIPT,  # TypeScript treated as JS for pattern matching
    ".tsx": Language.JAVASCRIPT,
}


class FileDiscovery:
    """Discover source files in a project directory."""

    def __init__(self, config: ScanConfig):
        self.config = config

    def discover(self, path: str) -> dict[Language, list[str]]:
        """Discover all scannable files in the given path.

        Returns a dict mapping Language to a list of file paths.
        """
        result: dict[Language, list[str]] = {
            lang: [] for lang in self.config.languages
        }
        result[Language.UNKNOWN] = []

        abs_path = os.path.abspath(path)
        if os.path.isfile(abs_path):
            lang = self._detect_language(abs_path)
            if lang in result:
                result[lang].append(abs_path)
            return result

        if not os.path.isdir(abs_path):
            return result

        for root, dirs, files in os.walk(abs_path):
            # Remove excluded directories in-place (modifies dirs to prevent recursion)
            dirs[:] = [
                d for d in dirs
                if d not in self.config.exclude_dirs
                and not self.config.is_excluded(os.path.join(root, d))
            ]

            for filename in files:
                filepath = os.path.join(root, filename)
                if self.config.is_excluded(filepath):
                    continue

                # Size check
                try:
                    size = os.path.getsize(filepath)
                    if size > self.config.max_file_size_mb * 1024 * 1024:
                        continue
                except OSError:
                    continue

                lang = self._detect_language(filepath)
                if lang in result and lang != Language.UNKNOWN:
                    result[lang].append(filepath)

        # Sort for deterministic output
        for lang in result:
            result[lang].sort()

        return result

    def _detect_language(self, filepath: str) -> Language:
        """Detect language from file extension."""
        ext = Path(filepath).suffix.lower()
        return EXTENSION_MAP.get(ext, Language.UNKNOWN)

    @staticmethod
    def get_relative_path(filepath: str, project_root: str) -> str:
        """Get a path relative to the project root, handling cross-drive issues."""
        try:
            return os.path.relpath(filepath, project_root)
        except ValueError:
            # Cross-drive on Windows
            return filepath
