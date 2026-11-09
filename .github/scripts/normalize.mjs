// Turns the raw output of each scanner into one findings.json with a common shape.
// Used by quality-scan.yml (TheChief) and repo-scan.yml (Repo Review). No dependencies.
//
// Output: .quality/findings.json
// {
//   runKey, sha, appDir, depsFixed, targetRepo, targetRef, fixDepsError, npmProjects, generatedAt,
//   tools:   [{ tool, status: ok|error|skipped, error, raw, findings, unique, highOrAbove, seconds }],
//   counts:  { total, bySeverity: {...}, byCategory: {...} },
//   findings: [{ id, tools[], severity, category, file, line, rule, cwe, message, fix,
//                package, installed, fixedIn, ids[] }]
// }
// severity: critical | high | medium | low | info
// category: vulnerability | bug | code_smell | dependency | secret | misconfiguration
//
// A tool may write one output file (<tool>.json) or one per project (<tool>.<slug>.json).
// For npm-audit, <tool>.<slug>.dir holds that project's folder.

import fs from 'node:fs';
import path from 'node:path';

const Q = '.quality';
const env = process.env;
const WS = (env.GITHUB_WORKSPACE || process.cwd()).replace(/\/+$/, '');
const selected = String(env.TOOLS || '').split(',').map(s => s.trim()).filter(Boolean);
const appDir = String(env.APP_DIR || '').replace(/^\.?\/*/, '').replace(/\/+$/, '');
const ALL_TOOLS = ['semgrep', 'osv', 'npm-audit', 'eslint', 'gitleaks', 'trivy'];
const OUTPUT = {
  semgrep: 'semgrep.json', osv: 'osv.json', 'npm-audit': 'npm-audit.json',
  eslint: 'eslint.json', gitleaks: 'gitleaks.json', trivy: 'trivy.json',
};
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const rank = s => { const i = SEV_ORDER.indexOf(s); return i < 0 ? 9 : i; };

function readJson(file) {
  const p = path.join(Q, file);
  if (!fs.existsSync(p)) return { missing: true };
  const text = fs.readFileSync(p, 'utf8').trim();
  if (!text) return { missing: true };
  try { return { data: JSON.parse(text) }; } catch (e) { return { error: 'Output is not valid JSON: ' + e.message }; }
}
function readText(file) {
  try { return fs.readFileSync(path.join(Q, file), 'utf8').trim(); } catch { return ''; }
}
function listQ() {
  try { return fs.readdirSync(Q); } catch { return []; }
}
function rel(p) {
  let s = String(p || '').replace(/\\/g, '/');
  for (const prefix of [WS + '/', '/src/', '/repo/', './']) if (s.startsWith(prefix)) s = s.slice(prefix.length);
  return s;
}
function sev(s) {
  s = String(s || '').toLowerCase();
  if (['critical', 'blocker'].includes(s)) return 'critical';
  if (['high', 'error', 'major'].includes(s)) return 'high';
  if (['medium', 'moderate', 'warning'].includes(s)) return 'medium';
  if (['low', 'minor'].includes(s)) return 'low';
  return 'info';
}
function sevFromScore(n) {
  n = Number(n);
  if (!(n > 0)) return '';
  if (n >= 9) return 'critical';
  if (n >= 7) return 'high';
  if (n >= 4) return 'medium';
  return 'low';
}
function cweOf(v) {
  const list = Array.isArray(v) ? v : (v ? [v] : []);
  const m = list.map(x => String(x).match(/CWE-\d+/i)).find(Boolean);
  return m ? m[0].toUpperCase() : '';
}

const raw = [];               // findings before de-duplication
const status = {};            // tool -> { status, error, raw }
const add = f => raw.push({
  tool: f.tool, rule: String(f.rule || ''), category: f.category,
  // A leaked secret is always at least high, whatever the tool says
  severity: f.category === 'secret' && rank(f.severity || 'info') > 1 ? 'high' : (f.severity || 'info'),
  file: rel(f.file), line: Number(f.line) || null, cwe: f.cwe || '', message: String(f.message || '').replace(/\s+/g, ' ').trim().slice(0, 500),
  fix: String(f.fix || '').slice(0, 300), package: f.package || '', installed: f.installed || '', fixedIn: f.fixedIn || '',
  ids: [...new Set((f.ids || []).filter(Boolean).map(String))],
  // For dependencies: the npm project folder, whether it is a direct dependency, and whether the fix is a major version change
  project: f.project !== undefined ? f.project : (f.category === 'dependency' ? (path.posix.dirname(rel(f.file)) || '.') : ''),
  direct: f.direct, majorUpgrade: !!f.majorUpgrade,
});

// ---------- parsers ----------
const parsers = {
  semgrep(d) {
    for (const r of d.results || []) {
      const md = (r.extra && r.extra.metadata) || {};
      const id = String(r.check_id || '');
      const cat = String(md.category || '').toLowerCase();
      let category = 'code_smell';
      if (/secret/i.test(id) || cat === 'secrets') category = 'secret';
      else if (cat === 'security') category = 'vulnerability';
      else if (cat === 'correctness') category = 'bug';
      add({
        tool: 'semgrep', rule: id, severity: sev(r.extra && r.extra.severity), category,
        file: r.path, line: r.start && r.start.line, cwe: cweOf(md.cwe), message: r.extra && r.extra.message,
        fix: r.extra && r.extra.fix,
      });
    }
    return (d.errors || []).filter(e => String(e.level || '').toLowerCase() === 'error').length
      ? 'Semgrep reported errors on some files' : '';
  },

  osv(d) {
    for (const res of d.results || []) {
      const file = res.source && res.source.path;
      for (const pkg of res.packages || []) {
        const name = pkg.package && pkg.package.name;
        const version = pkg.package && pkg.package.version;
        const groupScore = {};
        for (const g of pkg.groups || []) for (const id of g.ids || []) groupScore[id] = g.max_severity;
        for (const v of pkg.vulnerabilities || []) {
          let fixedIn = '';
          for (const a of v.affected || []) {
            if (a.package && a.package.name !== name) continue;
            for (const r of a.ranges || []) for (const ev of r.events || []) if (ev.fixed) fixedIn = ev.fixed;
          }
          const s = sev(v.database_specific && v.database_specific.severity);
          add({
            tool: 'osv', rule: v.id, severity: s !== 'info' ? s : (sevFromScore(groupScore[v.id]) || 'medium'),
            category: 'dependency', file, message: `${name}@${version}: ${v.summary || v.id}`,
            package: name, installed: version, fixedIn, ids: [v.id, ...(v.aliases || [])],
            cwe: cweOf(v.database_specific && v.database_specific.cwe_ids),
          });
        }
      }
    }
    return '';
  },

  'npm-audit'(d, ctx = {}) {
    if (d.error) return 'npm audit: ' + (d.error.summary || d.error.code || 'failed');
    const dir = ctx.dir !== undefined ? ctx.dir : appDir;
    const file = (dir ? dir + '/' : '') + 'package.json';
    for (const [name, v] of Object.entries(d.vulnerabilities || {})) {
      const fa = v.fixAvailable;
      const fix = fa === true ? 'npm audit fix'
        : (fa && typeof fa === 'object') ? `Update ${fa.name} to ${fa.version}${fa.isSemVerMajor ? ' (major version change)' : ''}` : '';
      const adv = (v.via || []).filter(x => x && typeof x === 'object');
      if (!adv.length) continue; // only transitive "via" another package; that package carries the advisory
      for (const a of adv) {
        const ghsa = (String(a.url || '').match(/GHSA-[\w-]+/i) || [])[0] || '';
        add({
          tool: 'npm-audit', rule: ghsa || String(a.source || a.title), severity: sev(a.severity), category: 'dependency',
          file, message: `${name}: ${a.title || 'vulnerable version range ' + (a.range || '')}`, fix,
          package: name, installed: '', fixedIn: (fa && typeof fa === 'object' && fa.name === name) ? fa.version : '',
          ids: [ghsa], cwe: cweOf(a.cwe), project: dir || '.', direct: !!v.isDirect,
          majorUpgrade: !!(fa && typeof fa === 'object' && fa.name === name && fa.isSemVerMajor),
        });
      }
    }
    return '';
  },

  eslint(d) {
    for (const f of Array.isArray(d) ? d : []) {
      for (const m of f.messages || []) {
        if (!m.ruleId) continue; // parse errors without a rule are reported below
        add({
          tool: 'eslint', rule: m.ruleId, severity: m.severity === 2 ? 'medium' : 'low',
          category: m.severity === 2 ? 'bug' : 'code_smell', file: f.filePath, line: m.line, message: m.message,
        });
      }
      for (const m of f.messages || []) if (!m.ruleId && m.fatal) {
        add({ tool: 'eslint', rule: 'parse-error', severity: 'high', category: 'bug', file: f.filePath, line: m.line, message: m.message });
      }
    }
    return '';
  },

  gitleaks(d) {
    for (const s of Array.isArray(d) ? d : []) {
      // Never copy the secret itself (Secret / Match) into the report
      add({
        tool: 'gitleaks', rule: s.RuleID, severity: 'high', category: 'secret', file: s.File, line: s.StartLine,
        message: `${s.Description || 'Possible secret'} (${s.RuleID}). Remove it from the code and rotate it.`,
        fix: 'Move the value to an environment variable or secret store, then rotate the exposed secret.',
      });
    }
    return '';
  },

  trivy(d) {
    for (const r of d.Results || []) {
      for (const v of r.Vulnerabilities || []) {
        add({
          tool: 'trivy', rule: v.VulnerabilityID, severity: sev(v.Severity), category: 'dependency', file: r.Target,
          message: `${v.PkgName}@${v.InstalledVersion}: ${v.Title || v.VulnerabilityID}`, package: v.PkgName,
          installed: v.InstalledVersion, fixedIn: v.FixedVersion || '', fix: v.FixedVersion ? `Update ${v.PkgName} to ${v.FixedVersion}` : '',
          ids: [v.VulnerabilityID, ...(v.VendorIDs || [])], cwe: cweOf(v.CweIDs),
        });
      }
      for (const m of r.Misconfigurations || []) {
        if (m.Status && m.Status !== 'FAIL') continue;
        add({
          tool: 'trivy', rule: m.ID || m.AVDID, severity: sev(m.Severity), category: 'misconfiguration', file: r.Target,
          line: m.CauseMetadata && m.CauseMetadata.StartLine, message: `${m.Title}: ${m.Message || ''}`, fix: m.Resolution,
        });
      }
      for (const s of r.Secrets || []) {
        add({
          tool: 'trivy', rule: s.RuleID, severity: sev(s.Severity), category: 'secret', file: r.Target, line: s.StartLine,
          message: `${s.Title || 'Possible secret'}. Remove it from the code and rotate it.`,
        });
      }
    }
    return '';
  },
};

// ---------- run parsers ----------
const listOutputs = tool => {
  const names = listQ();
  const many = names.filter(f => f.startsWith(tool + '.') && f.endsWith('.json') && f !== OUTPUT[tool]).sort();
  return names.includes(OUTPUT[tool]) ? [OUTPUT[tool], ...many] : many;
};
for (const tool of ALL_TOOLS) {
  if (!selected.includes(tool)) { status[tool] = { status: 'skipped' }; continue; }
  const before = raw.length;
  const errors = [readText(tool + '.error')].filter(Boolean);
  let parsedAny = false;
  for (const file of listOutputs(tool)) {
    const r = readJson(file);
    if (r.missing) continue;
    if (r.error) { errors.push(`${file}: ${r.error}`); continue; }
    const slug = file.slice(tool.length + 1, -'.json'.length);
    const ctx = slug ? { dir: readText(`${tool}.${slug}.dir`) } : {};
    try {
      const warning = parsers[tool](r.data, ctx);
      if (warning) errors.push(warning);
      parsedAny = true;
    } catch (e) { errors.push(`${file}: could not read output: ${e.message}`); }
  }
  for (const f of listQ()) if (f.startsWith(tool + '.') && f.endsWith('.error') && f !== tool + '.error') errors.push(readText(f));
  status[tool] = parsedAny
    ? { status: 'ok', error: errors.filter(Boolean).join(' | ').slice(0, 500), raw: raw.length - before }
    : { status: 'error', error: errors.filter(Boolean).join(' | ').slice(0, 500) || 'No output file. The scanner did not run or crashed.' };
}

// Ignore anything inside dependencies or build output
const IGNORE = /(^|\/)(node_modules|dist|build|coverage|\.quality)\//;
const kept = raw.filter(f => !(f.category !== 'dependency' && IGNORE.test(f.file)));

// ---------- de-duplicate across tools ----------
const merged = [];
for (const f of kept) {
  let hit;
  if (f.category === 'dependency') {
    hit = merged.find(m => m.category === 'dependency' && m.package === f.package && m.ids.some(id => f.ids.includes(id)));
  } else {
    // Same file and same line, and the same kind of problem (category or CWE)
    hit = merged.find(m => m.category !== 'dependency' && m.file === f.file && m.line && f.line &&
      m.line === f.line && (m.category === f.category || (m.cwe && m.cwe === f.cwe)));
  }
  if (hit) {
    if (!hit.tools.includes(f.tool)) hit.tools.push(f.tool);
    if (rank(f.severity) < rank(hit.severity)) hit.severity = f.severity;
    hit.ids = [...new Set([...hit.ids, ...f.ids])];
    if (!hit.rules.includes(f.rule)) hit.rules.push(f.rule);
    hit.fix = hit.fix || f.fix; hit.fixedIn = hit.fixedIn || f.fixedIn; hit.cwe = hit.cwe || f.cwe;
    hit.installed = hit.installed || f.installed;
    if (f.tool === 'npm-audit') { hit.project = f.project; hit.direct = f.direct; hit.majorUpgrade = f.majorUpgrade; if (f.fixedIn) hit.fixedIn = f.fixedIn; }
    else if (hit.direct === undefined) hit.direct = f.direct;
  } else {
    merged.push({ ...f, tools: [f.tool], rules: [f.rule] });
  }
}
merged.sort((a, b) => rank(a.severity) - rank(b.severity) || b.tools.length - a.tools.length || a.file.localeCompare(b.file));
const findings = merged.map((m, i) => ({
  id: 'F-' + String(i + 1).padStart(3, '0'), tools: m.tools, severity: m.severity, category: m.category,
  file: m.file, line: m.line, rule: m.rules.join(', '), cwe: m.cwe, message: m.message, fix: m.fix,
  package: m.package, installed: m.installed, fixedIn: m.fixedIn, ids: m.ids,
  ...(m.category === 'dependency' ? { project: m.project || '.', direct: m.direct === true, majorUpgrade: m.majorUpgrade } : {}),
}));

// ---------- per-tool stats ----------
const tools = ALL_TOOLS.map(tool => {
  const s = status[tool];
  const mine = findings.filter(f => f.tools.includes(tool));
  const secsText = readText(tool + '.seconds');
  const secs = Number(secsText);
  return {
    tool, status: s.status, error: s.error || '', raw: s.raw || 0, findings: mine.length,
    unique: mine.filter(f => f.tools.length === 1).length,
    highOrAbove: mine.filter(f => rank(f.severity) <= 1).length,
    seconds: secsText !== '' && Number.isFinite(secs) && secs >= 0 ? secs : null,
  };
});

const countBy = k => findings.reduce((o, f) => (o[f[k]] = (o[f[k]] || 0) + 1, o), {});
const npmDirsFile = path.join(Q, 'npm-dirs.txt');
const out = {
  runKey: env.RUN_KEY || '', sha: env.SHA || '', appDir, depsFixed: env.DEPS_FIXED === 'true',
  targetRepo: env.TARGET_REPO || '', targetRef: env.TARGET_REF || '', fixDepsError: readText('fix-deps.error'), fixDepsLog: readText('fix-deps.summary').split('\n').filter(Boolean).slice(0, 50),
  npmProjects: fs.existsSync(npmDirsFile)
    ? [...new Set(fs.readFileSync(npmDirsFile, 'utf8').split('\n').filter((l, i, a) => i < a.length - 1 || l !== '').map(l => l.trim() || '.'))]
    : [],
  generatedAt: new Date().toISOString(), selectedTools: selected,
  tools, counts: { total: findings.length, bySeverity: countBy('severity'), byCategory: countBy('category') },
  findings: findings.slice(0, 1000), truncated: findings.length > 1000,
};
fs.mkdirSync(Q, { recursive: true });
fs.writeFileSync(path.join(Q, 'findings.json'), JSON.stringify(out, null, 2));
console.log(`findings.json: ${findings.length} findings (${raw.length} before de-duplication)`);
for (const t of tools) if (t.status !== 'skipped') console.log(`  ${t.tool}: ${t.status} ${t.findings} findings, ${t.unique} only here${t.error ? ' - ' + t.error : ''}`);
