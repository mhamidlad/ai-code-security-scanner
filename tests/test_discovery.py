"""Tests for file discovery."""

from ai_scanner.discovery import FileDiscovery
from ai_scanner.models import ScanConfig, Language


class TestFileDiscovery:

    def test_discovers_python_files(self, tmp_path):
        (tmp_path / "app.py").write_text("# test")
        (tmp_path / "utils.py").write_text("# test")

        discovery = FileDiscovery(ScanConfig())
        result = discovery.discover(str(tmp_path))

        assert len(result[Language.PYTHON]) == 2

    def test_discovers_javascript_files(self, tmp_path):
        (tmp_path / "app.js").write_text("// test")
        (tmp_path / "utils.mjs").write_text("// test")
        (tmp_path / "module.cjs").write_text("// test")

        discovery = FileDiscovery(ScanConfig())
        result = discovery.discover(str(tmp_path))

        assert len(result[Language.JAVASCRIPT]) == 3

    def test_discovers_typescript_files(self, tmp_path):
        (tmp_path / "app.ts").write_text("// test")
        (tmp_path / "component.tsx").write_text("// test")

        discovery = FileDiscovery(ScanConfig())
        result = discovery.discover(str(tmp_path))

        assert len(result[Language.JAVASCRIPT]) == 2

    def test_excludes_node_modules(self, tmp_path):
        (tmp_path / "index.py").write_text("# test")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "lib.js").write_text("// test")

        discovery = FileDiscovery(ScanConfig())
        result = discovery.discover(str(tmp_path))

        assert len(result[Language.PYTHON]) == 1
        assert len(result[Language.JAVASCRIPT]) == 0

    def test_excludes_venv(self, tmp_path):
        (tmp_path / "app.py").write_text("# test")
        (tmp_path / "venv").mkdir()
        (tmp_path / "venv" / "site-packages.py").write_text("# test")

        discovery = FileDiscovery(ScanConfig())
        result = discovery.discover(str(tmp_path))

        assert len(result[Language.PYTHON]) == 1

    def test_excludes_build_dirs(self, tmp_path):
        (tmp_path / "app.py").write_text("# test")
        (tmp_path / "dist").mkdir()
        (tmp_path / "dist" / "bundle.js").write_text("// test")
        (tmp_path / "build").mkdir()
        (tmp_path / "build" / "output.js").write_text("// test")

        discovery = FileDiscovery(ScanConfig())
        result = discovery.discover(str(tmp_path))

        assert len(result[Language.PYTHON]) == 1
        assert len(result[Language.JAVASCRIPT]) == 0

    def test_single_file_input(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text("# test")

        discovery = FileDiscovery(ScanConfig())
        result = discovery.discover(str(f))

        assert len(result[Language.PYTHON]) == 1

    def test_custom_exclude_dirs(self, tmp_path):
        (tmp_path / "app.py").write_text("# test")
        (tmp_path / "custom_dir").mkdir()
        (tmp_path / "custom_dir" / "lib.py").write_text("# test")

        config = ScanConfig(exclude_dirs=["custom_dir"])
        discovery = FileDiscovery(config)
        result = discovery.discover(str(tmp_path))

        assert len(result[Language.PYTHON]) == 1

    def test_file_size_limit(self, tmp_path):
        f = tmp_path / "large.py"
        f.write_text("x" * (11 * 1024 * 1024))  # 11MB

        discovery = FileDiscovery(ScanConfig())
        result = discovery.discover(str(tmp_path))

        assert len(result[Language.PYTHON]) == 0

    def test_non_python_js_files_ignored(self, tmp_path):
        (tmp_path / "app.py").write_text("# test")
        (tmp_path / "readme.md").write_text("# test")
        (tmp_path / "data.json").write_text("{}")
        (tmp_path / "style.css").write_text("body{}")

        discovery = FileDiscovery(ScanConfig())
        result = discovery.discover(str(tmp_path))

        assert len(result[Language.PYTHON]) == 1
        assert len(result[Language.JAVASCRIPT]) == 0
