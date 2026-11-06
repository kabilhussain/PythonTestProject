# Planted Bug Catalogue

This project is **intentionally broken**. Use it to check what SonarQube and other analyzers catch.
Each bug is tagged in the source with a comment like `# BUG S4:`.

| Prefix | File | Category | Count |
|---|---|---|---|
| S | `buggy_app/security_issues.py` | Security vulnerabilities / hotspots | 20 |
| L | `buggy_app/logic_bugs.py` | Reliability / runtime bugs | 25 |
| C | `buggy_app/code_smells.py` | Maintainability / code smells | 19 |
| I | `buggy_app/inventory.py` | Subtle logic + type-annotation bugs | 9 |
| D | `requirements.txt` | Vulnerable dependencies (SCA) | 6 pkgs |

Highlights:
- **S**: hard-coded secrets, SQL injection, command injection, `eval`/`exec`, `pickle`, unsafe YAML, MD5/SHA1, weak PRNG, `mktemp`, `chmod 777`, XXE, path traversal, `verify=False`, bind `0.0.0.0`, `assert` for auth, Flask `debug=True`.
- **L**: mutable default arg, division by zero, `== None`, `is` on literals, bare except, swallowed exceptions, off-by-one, unbound variable, mutate-while-iterating, identical branches, dead code, float equality, format-arg mismatch, infinite loop, `raise NotImplemented`, resource leak, infinite recursion, str+int.
- **C**: wildcard/unused imports, naming, too many params, `global`, `__eq__` without `__hash__`, deep nesting/complexity, triplicated code, magic numbers, TODO/FIXME, commented-out code, long lines, whitespace, too many returns, lambda assignment, debug prints.
- **I**: overwrite instead of accumulate, negative stock, `.sort()` returns `None`, wrong return annotations, `min()` on empty, percent vs fraction.

## Tools
| Tool | What it checks | Run via |
|---|---|---|
| SonarQube | bugs, vulns, hotspots, smells, duplication, coverage | `./run_sonar.sh` |
| Bandit | security | `./run_analysis.sh` |
| Pylint / Flake8 / Ruff | lint, style, bugs, complexity | `./run_analysis.sh` |
| Mypy | type errors | `./run_analysis.sh` |
| Radon | cyclomatic complexity, maintainability index | `./run_analysis.sh` |
| Vulture | dead code | `./run_analysis.sh` |
| pip-audit | known CVEs in dependencies | `./run_analysis.sh` |
| pytest-cov | failing tests + coverage | `./run_analysis.sh` |

## Usage
```bash
./run_analysis.sh          # local tools -> reports/*
./run_sonar.sh             # SonarQube in Docker; imports the reports above
python3 generate_report.py # -> reports/REPORT.md + reports/report.html (detection matrix)
```
Run `./run_analysis.sh` **first** so SonarQube can import the coverage and external-linter reports.
Stop SonarQube with `docker compose down` (add `-v` to delete its data).
