const axios = require('axios');

const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';

function extractFixed(vuln) {
  try {
    for (const affected of (vuln.affected || [])) {
      for (const range of (affected.ranges || [])) {
        for (const event of (range.events || [])) {
          if (event.fixed) return event.fixed;
        }
      }
    }
  } catch {}
  return null;
}

async function batchQueryOSV(cveIds) {
  if (!cveIds.length) return {};
  const unique = [...new Set(cveIds)].slice(0, 50);
  try {
    const res = await axios.post(OSV_BATCH, { queries: unique.map(id => ({ id })) }, { timeout: 20000 });
    const enriched = {};
    (res.data.results || []).forEach((result, i) => {
      const vuln = result.vulns?.[0];
      if (!vuln) return;
      enriched[unique[i]] = {
        summary: vuln.summary || '',
        details: (vuln.details || '').slice(0, 400),
        aliases: (vuln.aliases || []).slice(0, 3),
        references: (vuln.references || []).slice(0, 2).map(r => r.url),
        fixed: extractFixed(vuln),
        cvssScore: vuln.severity?.[0]?.score || null,
      };
    });
    return enriched;
  } catch (e) {
    console.warn('[OSV] batch query failed:', e.message);
    return {};
  }
}

async function enrichTrivyReport(content) {
  try {
    const data = JSON.parse(content);
    const results = data.Results || [];

    const cveIds = results.flatMap(r =>
      (r.Vulnerabilities || [])
        .map(v => v.VulnerabilityID)
        .filter(id => id && id.startsWith('CVE-'))
    );

    if (!cveIds.length) return content;

    const osvMap = await batchQueryOSV(cveIds);
    if (!Object.keys(osvMap).length) return content;

    return JSON.stringify({
      ...data,
      Results: results.map(r => ({
        ...r,
        Vulnerabilities: (r.Vulnerabilities || []).map(v => ({
          ...v,
          OSV: osvMap[v.VulnerabilityID] || null,
        })),
      })),
    });
  } catch (e) {
    console.warn('[OSV] enrichTrivyReport failed:', e.message);
    return content;
  }
}

module.exports = { enrichTrivyReport, batchQueryOSV };
