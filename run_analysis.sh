#!/usr/bin/env bash
# Runs all local static-analysis tools and writes their output to reports/.
# Tools exit non-zero when they find issues; that's expected, so we don't use `set -e`.
set -u
cd "$(dirname "$0")"
PY=.venv/bin
mkdir -p reports

echo "==> pytest + coverage"
$PY/pytest --cov=buggy_app --cov-report=xml:reports/coverage.xml \
  --junitxml=reports/pytest-junit.xml -q > reports/pytest.txt 2>&1

echo "==> bandit (security)"
$PY/bandit -r buggy_app -f json -o reports/bandit.json -q
$PY/bandit -r buggy_app -f txt -o reports/bandit.txt -q

echo "==> pylint"
$PY/pylint buggy_app --exit-zero \
  --msg-template='{path}:{line}: [{msg_id}({symbol}), {obj}] {msg}' > reports/pylint.txt

echo "==> flake8"
$PY/flake8 buggy_app --exit-zero --max-complexity=10 > reports/flake8.txt

echo "==> ruff"
$PY/ruff check buggy_app --exit-zero --output-format=json > reports/ruff.json
$PY/ruff check buggy_app --exit-zero --output-format=concise > reports/ruff.txt

echo "==> mypy (types)"
$PY/mypy buggy_app --ignore-missing-imports --check-untyped-defs > reports/mypy.txt 2>&1

echo "==> radon (complexity)"
$PY/radon cc buggy_app -s -n C > reports/radon_cc.txt
$PY/radon mi buggy_app -s > reports/radon_mi.txt

echo "==> vulture (dead code)"
$PY/vulture buggy_app --min-confidence 60 > reports/vulture.txt

echo "==> pip-audit (vulnerable dependencies)"
$PY/pip-audit -r requirements.txt --no-deps --disable-pip -f json -o reports/pip-audit.json 2>/dev/null
$PY/pip-audit -r requirements.txt --no-deps --disable-pip > reports/pip-audit.txt 2>&1

echo "Done. Reports in ./reports/"
