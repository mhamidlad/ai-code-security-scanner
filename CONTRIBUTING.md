# Contributing

Thank you for your interest in improving the AI Code Security Scanner.

## How to Contribute

1. **Fork** the repository.
2. **Clone** your fork locally.
3. **Create a branch**: `git checkout -b fix/my-improvement`
4. **Make your changes** and add tests.
5. **Run tests**: `python -m pytest -v`
6. **Commit** with a clear message.
7. **Push** and open a pull request.

## Development Setup

```bash
git clone https://github.com/mhamidlad/ai-code-security-scanner.git
cd ai-code-security-scanner
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

## Adding a New Rule

1. Define the rule in `src/ai_scanner/rules/python_rules.py` or `javascript_rules.py`.
2. Add a test in `tests/test_python_rules.py` or `tests/test_javascript_rules.py`.
3. Add vulnerable and secure examples in `examples/`.
4. Ensure all tests pass: `python -m pytest -v`.

## Code Standards

- Follow PEP 8 for Python code.
- Write docstrings for all public functions and classes.
- Add type hints where possible.
- Keep functions focused and small.
- Every new rule must have at least one positive and one negative test.

## Reporting Issues

Use GitHub Issues for bug reports and feature requests. For security
vulnerabilities in the scanner itself, see [SECURITY.md](SECURITY.md).
