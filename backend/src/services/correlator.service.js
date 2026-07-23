const SEV_RANK = { CRITICAL: 0, BLOCKER: 0, HIGH: 1, MAJOR: 1, MEDIUM: 2, MINOR: 3, LOW: 3, INFO: 4, UNKNOWN: 5 };

function parseGitleaks(content) {
  try {
    const arr = JSON.parse(content || '[]');
    if (!Array.isArray(arr)) return [];
    return arr.map(f => ({
      tool: 'gitleaks', type: 'secret', severity: 'CRITICAL',
      file: f.File || f.file || '',
      line: f.StartLine || null,
      title: f.RuleID || f.ruleId || 'Secret Detected',
      detail: f.Description || (f.Secret ? f.Secret.slice(0, 60) + '...' : ''),
    }));
  } catch { return []; }
}

function parseSemgrep(content) {
  try {
    const data = JSON.parse(content || '{}');
    if (data.status !== 'OK') return [];
    return (data.issues?.issues || []).map(issue => ({
      tool: 'sonarqube', type: issue.type || 'VULNERABILITY',
      severity: issue.severity === 'BLOCKER' ? 'CRITICAL' : issue.severity === 'CRITICAL' ? 'CRITICAL' : issue.severity === 'MAJOR' ? 'HIGH' : 'MEDIUM',
      file: issue.component?.split(':').pop() || '',
      line: issue.line || null,
      title: issue.message || 'SonarQube Issue',
      detail: issue.rule || '',
    }));
  } catch { return []; }
}

function parseOwasp(content) {
  try {
    const data = JSON.parse(content || '{}');
    const results = (data.Results || []).filter(r => r.Vulnerabilities?.length);
    return results.flatMap(r =>
      (r.Vulnerabilities || []).map(v => ({
        tool: 'trivy-fs', type: 'dependency',
        severity: v.Severity || 'UNKNOWN',
        file: r.Target || '',
        line: null,
        title: `${v.VulnerabilityID} in ${v.PkgName}@${v.InstalledVersion}`,
        detail: v.Title || '',
        fix: v.FixedVersion || v.OSV?.fixed || null,
        cveId: v.VulnerabilityID,
      }))
    );
  } catch { return []; }
}

function parseCheckov(content) {
  try {
    const raw = JSON.parse(content || '{}');
    const reports = Array.isArray(raw) ? raw : [raw];
    return reports.flatMap(r => r.results?.failed_checks || []).map(f => ({
      tool: 'checkov', type: 'iac',
      severity: f.severity === 'HIGH' || f.severity === 'CRITICAL' ? f.severity : 'MEDIUM',
      file: f.repo_file_path || f.file_path || '',
      line: f.file_line_range?.[0] || null,
      title: f.check?.name || f.check_id || 'IaC Misconfiguration',
      detail: f.check_id || '',
    }));
  } catch { return []; }
}

function buildCorrelatedReport({ gitleaks, semgrep, owasp, checkov }) {
  const all = [
    ...parseGitleaks(gitleaks),
    ...parseSemgrep(semgrep),
    ...parseOwasp(owasp),
    ...parseCheckov(checkov),
  ];

  // Group by normalized file path
  const byFile = {};
  for (const f of all) {
    const key = (f.file || '').toLowerCase().replace(/^\//, '') || '__no_file__';
    if (!byFile[key]) byFile[key] = { file: f.file || '', findings: [] };
    byFile[key].findings.push(f);
  }

  const items = Object.values(byFile).map(group => {
    const tools = [...new Set(group.findings.map(f => f.tool))];
    const worstSev = group.findings.reduce((best, f) => {
      return (SEV_RANK[f.severity] ?? 5) < (SEV_RANK[best] ?? 5) ? f.severity : best;
    }, 'UNKNOWN');

    // Bump severity for multi-tool hits on same file
    let effectiveSev = worstSev;
    if (tools.length >= 2 && SEV_RANK[worstSev] >= 2) effectiveSev = 'HIGH';
    if (tools.length >= 3) effectiveSev = 'CRITICAL';

    return {
      file: group.file,
      tools,
      toolCount: tools.length,
      severity: effectiveSev,
      multiTool: tools.length > 1,
      findings: group.findings,
    };
  });

  // Sort: multi-tool first, then worst severity
  items.sort((a, b) => {
    if (b.multiTool !== a.multiTool) return b.multiTool ? 1 : -1;
    return (SEV_RANK[a.severity] ?? 5) - (SEV_RANK[b.severity] ?? 5);
  });

  return {
    totalFindings: all.length,
    uniqueFiles: items.length,
    multiToolHits: items.filter(i => i.multiTool).length,
    criticalCount: items.filter(i => i.severity === 'CRITICAL').length,
    highCount: items.filter(i => i.severity === 'HIGH').length,
    toolBreakdown: {
      secrets: all.filter(f => f.tool === 'gitleaks').length,
      sast: all.filter(f => f.tool === 'sonarqube').length,
      dependencies: all.filter(f => f.tool === 'trivy-fs').length,
      iac: all.filter(f => f.tool === 'checkov').length,
    },
    items,
  };
}

module.exports = { buildCorrelatedReport };
