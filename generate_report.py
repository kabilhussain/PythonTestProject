"""Build a consolidated report (reports/REPORT.md + reports/report.html) from all tool outputs.

For every planted `# BUG Xn:` tag it checks which tools flagged a line in that bug's
region, so you get a detection matrix: which analyzer catches which kind of bug.
Run after ./run_analysis.sh and ./run_sonar.sh.
"""
import html
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).parent
REP = ROOT / "reports"
SRC = ROOT / "buggy_app"
TOOLS = ["SonarQube", "Bandit", "Pylint", "Flake8", "Ruff", "Mypy", "Vulture", "Radon"]
BUG_RE = re.compile(r"#\s*BUG ([A-Z]\d+):\s*(.*)")
DEF_RE = re.compile(r"^\s*(def|class) ")
# Findings that fire on nearly every function regardless of the planted bug (don't credit them).
NOISE = re.compile(r"missing-(function|class|module)-docstring|unused (function|class|method)|"
                   r"^C011[456] ")


def rel(path):
    p = str(path).replace("\\", "/")
    i = p.find("buggy_app/")
    return p[i:] if i >= 0 else p


def load(name, default=None):
    f = REP / name
    if not f.exists():
        return default
    return json.loads(f.read_text()) if name.endswith(".json") else f.read_text()


# ---------- collect planted bugs and their line windows ----------
def planted_bugs():
    bugs = []
    for f in sorted(SRC.glob("*.py")):
        lines = f.read_text().splitlines()
        n = len(lines)
        defs = [i for i, line in enumerate(lines, 1) if DEF_RE.match(line)]
        for ln, line in enumerate(lines, 1):
            m = BUG_RE.search(line)
            if not m:
                continue
            code_before = line.split("#")[0].strip()
            enclosing = max((d for d in defs if d <= ln), default=None)
            nxt = min((d for d in defs if d > ln), default=n + 1)
            if code_before and not DEF_RE.match(line):
                start, end = ln, ln  # inline comment on an ordinary statement
            elif enclosing is None or (not code_before and not line.startswith(" ")):
                # module-level comment: covers lines until next blank line
                start, end = ln, ln
                while end < n and lines[end].strip():
                    end += 1
            else:
                start = ln if DEF_RE.match(line) else enclosing
                end = nxt - 1
            bugs.append({"id": m.group(1), "desc": m.group(2).strip(), "file": rel(f),
                         "line": ln, "start": start, "end": end})
    return bugs


# ---------- collect findings per tool: list of (file, line, rule, message) ----------
def findings():
    out = defaultdict(list)
    sonar = load("sonar-issues.json", {}) or {}
    for i in sonar.get("issues", []):
        if i["rule"].startswith("python:"):  # native Sonar rules only
            out["SonarQube"].append((rel(i["component"].split(":", 1)[1]), i.get("line", 0),
                                     i["rule"], f'[{i["type"]}/{i["severity"]}] {i["message"]}'))
    for h in (load("sonar-hotspots.json", {}) or {}).get("hotspots", []):
        out["SonarQube"].append((rel(h["component"].split(":", 1)[1]), h.get("line", 0),
                                 h["ruleKey"], "[HOTSPOT] " + h["message"]))
    for r in (load("bandit.json", {}) or {}).get("results", []):
        out["Bandit"].append((rel(r["filename"]), r["line_number"], r["test_id"],
                              f'[{r["issue_severity"]}] {r["issue_text"]}'))
    for r in load("ruff.json", []) or []:
        out["Ruff"].append((rel(r["filename"]), r["location"]["row"], r["code"] or "", r["message"]))
    patterns = {
        "Pylint": ("pylint.txt", re.compile(r"^(buggy_app/\S+):(\d+): \[(\w+)\(([\w-]+)\).*?\] (.*)")),
        "Flake8": ("flake8.txt", re.compile(r"^(\S+):(\d+):\d+: (\w+) (.*)")),
        "Mypy": ("mypy.txt", re.compile(r"^(\S+):(\d+): error: (.*)")),
        "Vulture": ("vulture.txt", re.compile(r"^(\S+):(\d+): (.*)")),
    }
    for tool, (fname, rx) in patterns.items():
        for line in (load(fname, "") or "").splitlines():
            m = rx.match(line)
            if not m:
                continue
            g = m.groups()
            if tool == "Pylint":
                out[tool].append((rel(g[0]), int(g[1]), f"{g[2]} {g[3]}", g[4]))
            elif tool == "Flake8":
                out[tool].append((rel(g[0]), int(g[1]), g[2], g[3]))
            else:
                out[tool].append((rel(g[0]), int(g[1]), tool.lower(), g[2]))
    cur = None
    for line in (load("radon_cc.txt", "") or "").splitlines():
        if line.startswith("buggy_app"):
            cur = line.strip()
        else:
            m = re.match(r"\s+\w (\d+):\d+ (\S+) - ([A-F]) \((\d+)\)", line)
            if m and cur:
                out["Radon"].append((cur, int(m.group(1)), "CC-" + m.group(3),
                                     f"{m.group(2)} complexity {m.group(4)}"))
    return out


def main():
    bugs = planted_bugs()
    found = findings()
    matrix = {}
    for b in bugs:
        row = {}
        for t in TOOLS:
            hits = [f for f in found.get(t, []) if f[0] == b["file"] and b["start"] <= f[1] <= b["end"]]
            row[t] = [h for h in hits if not NOISE.search(f"{h[2]} {h[3]}")]
        matrix[b["id"]] = row

    cats = {"S": "Security", "L": "Logic / reliability", "C": "Code smell", "I": "Inventory (subtle)"}
    per_tool = {t: sum(1 for b in bugs if matrix[b["id"]][t]) for t in TOOLS}
    per_cat_tool = {c: {t: sum(1 for b in bugs if b["id"][0] == c and matrix[b["id"]][t]) for t in TOOLS}
                    for c in cats}
    cat_totals = Counter(b["id"][0] for b in bugs)
    caught_any = sum(1 for b in bugs if any(matrix[b["id"]].values()))
    missed = [b for b in bugs if not any(matrix[b["id"]].values())]

    measures = {m["metric"]: m.get("value") for m in
                (load("sonar-measures.json", {}) or {}).get("component", {}).get("measures", [])}
    gate = (load("sonar-qualitygate.json", {}) or {}).get("projectStatus", {}).get("status", "n/a")
    pytest_txt = load("pytest.txt", "") or ""
    pytest_summary = (re.findall(r"^=*\s*(\d+ failed.*|\d+ passed.*?)\s*=*$", pytest_txt, re.M) or ["n/a"])[-1]
    failed_tests = re.findall(r"^FAILED (\S+)", pytest_txt, re.M)
    audit = load("pip-audit.json", {}) or {}
    deps = [(d["name"], d["version"], sorted({v["id"] for v in d.get("vulns", [])})) for d in audit.get("dependencies", [])]

    # ---------- Markdown ----------
    md = ["# Static Analysis Report: buggy_app", ""]
    md += [f"**Planted bugs:** {len(bugs)}  |  **Caught by at least one tool:** {caught_any} "
           f"({caught_any * 100 // len(bugs)}%)  |  **Missed by all:** {len(missed)}", ""]
    md += ["## SonarQube metrics", "", "| Metric | Value |", "|---|---|"]
    for k in ["bugs", "vulnerabilities", "code_smells", "security_hotspots", "coverage",
              "duplicated_lines_density", "cognitive_complexity", "ncloc",
              "reliability_rating", "security_rating", "sqale_rating"]:
        md.append(f"| {k} | {measures.get(k, 'n/a')} |")
    md += [f"| quality gate | {gate} |", "",
           "_Sonar counts include issues imported from Bandit/Pylint/Ruff/Flake8/Mypy; "
           "the matrix below counts only Sonar's own rules._", ""]
    md += ["## Detection rate per tool (planted bugs caught)", "",
           "| Category | Total | " + " | ".join(TOOLS) + " |", "|---|---|" + "---|" * len(TOOLS)]
    for c, name in cats.items():
        md.append(f"| {name} | {cat_totals[c]} | " + " | ".join(str(per_cat_tool[c][t]) for t in TOOLS) + " |")
    md.append(f"| **All** | **{len(bugs)}** | " + " | ".join(f"**{per_tool[t]}**" for t in TOOLS) + " |")
    md += ["", "## Bug-by-bug matrix", "", "| Bug | Description | " + " | ".join(TOOLS) + " |",
           "|---|---|" + "---|" * len(TOOLS)]
    for b in bugs:
        md.append(f"| {b['id']} | {b['desc']} | " +
                  " | ".join("✔" if matrix[b["id"]][t] else "" for t in TOOLS) + " |")
    md += ["", "## Missed by every tool", ""] + [f"- **{b['id']}** {b['desc']} (`{b['file']}:{b['line']}`)" for b in missed]
    md += ["", "## Tests", "", f"`{pytest_summary}`", ""] + [f"- FAILED `{t}`" for t in failed_tests]
    md += ["", "## Vulnerable dependencies (pip-audit)", "", "| Package | Version | Advisories |", "|---|---|---|"]
    md += [f"| {n} | {v} | {len(ids)} |" for n, v, ids in deps]
    md += ["", "## Raw finding counts per tool", ""] + [f"- {t}: {len(found.get(t, []))}" for t in TOOLS]
    (REP / "REPORT.md").write_text("\n".join(md) + "\n")

    # ---------- HTML ----------
    def cell(hits):
        if not hits:
            return '<td class="no">·</td>'
        tip = html.escape("\n".join(f"L{h[1]} {h[2]}: {h[3]}" for h in hits[:6]))
        return f'<td class="yes" title="{tip}">✔</td>'

    rows = "".join(
        f'<tr><td class="id">{b["id"]}</td><td class="desc">{html.escape(b["desc"])}'
        f'<span class="loc">{b["file"]}:{b["line"]}</span></td>'
        + "".join(cell(matrix[b["id"]][t]) for t in TOOLS) + "</tr>" for b in bugs)
    cat_rows = "".join(
        f"<tr><td>{n}</td><td>{cat_totals[c]}</td>" + "".join(
            f'<td style="--p:{per_cat_tool[c][t] / max(cat_totals[c], 1):.2f}" class="pct">{per_cat_tool[c][t]}</td>'
            for t in TOOLS) + "</tr>" for c, n in cats.items())
    metric_cards = "".join(
        f'<div class="m"><span>{html.escape(k.replace("_", " "))}</span><b>{html.escape(str(measures.get(k, "n/a")))}</b></div>'
        for k in ["bugs", "vulnerabilities", "code_smells", "coverage", "duplicated_lines_density", "cognitive_complexity"])
    dep_rows = "".join(f"<tr><td>{n}</td><td>{v}</td><td>{len(ids)}</td></tr>" for n, v, ids in deps)
    missed_li = "".join(f"<li><b>{b['id']}</b> {html.escape(b['desc'])} <span class='loc'>{b['file']}:{b['line']}</span></li>" for b in missed)
    tests_li = "".join(f"<li><code>{html.escape(t)}</code></li>" for t in failed_tests)
    head = "".join(f"<th>{t}</th>" for t in TOOLS)
    page = f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>buggy_app Analysis</title><style>
:root{{--bg:#f6f7f9;--fg:#1c2230;--mut:#5d6677;--card:#fff;--line:#dfe3ea;--ok:#1f8a4c;--okbg:#e3f4ea;--bad:#b4232a;--acc:#2f5bd3}}
@media (prefers-color-scheme:dark){{:root{{--bg:#12151c;--fg:#e4e8f0;--mut:#9aa3b5;--card:#1a1f29;--line:#2c3341;--ok:#5fd394;--okbg:#173527;--bad:#ff7b7f;--acc:#86a5ff;color-scheme:dark}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif;padding:24px max(16px,4vw)}}
h1{{margin:0 0 4px;font-size:24px}} h2{{font-size:17px;margin:32px 0 10px}} .sub{{color:var(--mut)}}
.ms{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-top:16px}}
.m{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}}
.m span{{display:block;color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em}} .m b{{font-size:22px;font-variant-numeric:tabular-nums}}
.wrap{{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px}}
table{{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}} th,td{{padding:6px 10px;border-bottom:1px solid var(--line);text-align:center}}
th{{font-size:12px;color:var(--mut);position:sticky;top:0;background:var(--card)}} td.desc,td:first-child{{text-align:left}}
td.id{{font-weight:600;font-family:ui-monospace,monospace}} .loc{{display:block;color:var(--mut);font:11px ui-monospace,monospace}}
td.yes{{color:var(--ok);background:var(--okbg);font-weight:700;cursor:help}} td.no{{color:var(--line)}}
td.pct{{background:color-mix(in srgb,var(--ok) calc(var(--p)*45%),transparent)}}
.miss li{{margin:4px 0}} .miss b{{color:var(--bad)}}
</style></head><body>
<h1>buggy_app static analysis</h1>
<div class="sub">{len(bugs)} planted bugs · {caught_any} caught by at least one tool ({caught_any * 100 // len(bugs)}%) · {len(missed)} missed by all · Sonar quality gate: <b>{gate}</b> · tests: {html.escape(pytest_summary)}</div>
<div class="ms">{metric_cards}</div>
<h2>Detection by category</h2><div class="wrap"><table><tr><th>Category</th><th>Planted</th>{head}</tr>{cat_rows}
<tr><td><b>All</b></td><td><b>{len(bugs)}</b></td>{"".join(f"<td><b>{per_tool[t]}</b></td>" for t in TOOLS)}</tr></table></div>
<h2>Missed by every tool</h2><ul class="miss">{missed_li or "<li>None</li>"}</ul>
<h2>Bug-by-bug matrix <span class="sub">(hover a ✔ to see the finding)</span></h2>
<div class="wrap"><table><tr><th>Bug</th><th>Description</th>{head}</tr>{rows}</table></div>
<h2>Failing tests</h2><ul>{tests_li}</ul>
<h2>Vulnerable dependencies (pip-audit)</h2><div class="wrap"><table><tr><th>Package</th><th>Version</th><th>Advisories</th></tr>{dep_rows}</table></div>
<p class="sub">SonarQube column counts native Sonar rules only; Sonar's headline counts also include imported Bandit/Pylint/Ruff/Flake8/Mypy issues. A tool is credited when it flags any line in the bug's function or statement.</p>
</body></html>"""
    (REP / "report.html").write_text(page)
    print(f"Planted: {len(bugs)}  caught: {caught_any}  missed: {len(missed)}")
    for t in TOOLS:
        print(f"  {t:10s} {per_tool[t]:3d} / {len(bugs)}")
    print("Wrote reports/REPORT.md and reports/report.html")


if __name__ == "__main__":
    main()
