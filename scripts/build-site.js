import { readFile, writeFile, mkdir } from "fs/promises"

async function buildSite() {
  let digest
  try {
    digest = JSON.parse(await readFile("data/digest.json", "utf-8"))
  } catch {
    console.error("No digest found. Run 'npm run analyze' first.")
    process.exit(1)
  }

  const periodStart = new Date(digest.period?.start).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })
  const periodEnd = new Date(digest.period?.end).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })
  const generatedAt = new Date(digest.generatedAt).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" })

  const highlightsHtml = (digest.highlights || []).map(h => `
    <div class="card highlight">
      <div class="card-header">
        <span class="severity-badge ${(h.severity || '').toLowerCase()}">${h.severity || 'N/A'}</span>
        <h3>${escapeHtml(h.title)}</h3>
      </div>
      <div class="cve-ids">${(h.cveIds || []).map(id => `<code>${escapeHtml(id)}</code>`).join(" ")}</div>
      <p><strong>Impact:</strong> ${escapeHtml(h.impact || '')}</p>
      <p><strong>Supply Chain Relevance:</strong> ${escapeHtml(h.supplyChainRelevance || '')}</p>
    </div>
  `).join("")

  const risksHtml = (digest.supplyChainRisks || []).map(r => `
    <div class="card risk">
      <h3>⚠️ ${escapeHtml(r.risk)}</h3>
      <p><strong>Affected Area:</strong> <span class="tag">${escapeHtml(r.affectedArea || '')}</span></p>
      <p><strong>Mitigation:</strong> ${escapeHtml(r.mitigation || '')}</p>
    </div>
  `).join("")

  const recommendationsHtml = (digest.recommendations || []).map(r => 
    `<li>${escapeHtml(r)}</li>`
  ).join("")

  const topCVEsHtml = (digest.topCVEs || []).map(c => `
    <tr>
      <td><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.id)}" target="_blank">${escapeHtml(c.id)}</a></td>
      <td><span class="severity-badge ${c.score >= 9 ? 'critical' : 'high'}">${c.score}</span></td>
      <td>${escapeHtml(c.attackVector || '')}</td>
      <td>${escapeHtml((c.description || '').substring(0, 120))}${(c.description || '').length > 120 ? '...' : ''}</td>
    </tr>
  `).join("")

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Security Digest — Supply Chain Intelligence</title>
  <meta name="description" content="AI-powered weekly software supply chain security intelligence briefs">
  <style>
    :root {
      --bg: #0d1117;
      --surface: #161b22;
      --border: #30363d;
      --text: #e6edf3;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --critical: #f85149;
      --high: #db6d28;
      --green: #3fb950;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
    }
    .container { max-width: 960px; margin: 0 auto; padding: 2rem 1.5rem; }
    header {
      text-align: center;
      padding: 3rem 0 2rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 2rem;
    }
    header h1 { font-size: 2.2rem; margin-bottom: 0.5rem; }
    header h1 span { color: var(--accent); }
    header .subtitle { color: var(--text-muted); font-size: 1.1rem; }
    .period { color: var(--text-muted); font-size: 0.9rem; margin-top: 1rem; }
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 1rem;
      margin: 2rem 0;
    }
    .stat {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.2rem;
      text-align: center;
    }
    .stat .number { font-size: 2rem; font-weight: 700; }
    .stat .label { color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; }
    .stat .number.critical { color: var(--critical); }
    .stat .number.high { color: var(--high); }
    .stat .number.accent { color: var(--accent); }
    section { margin-bottom: 2.5rem; }
    section > h2 {
      font-size: 1.4rem;
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid var(--border);
    }
    .summary-box {
      background: var(--surface);
      border-left: 4px solid var(--accent);
      padding: 1.2rem 1.5rem;
      border-radius: 0 8px 8px 0;
      font-size: 1.05rem;
      margin-bottom: 2rem;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.2rem 1.5rem;
      margin-bottom: 1rem;
    }
    .card-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; }
    .card-header h3 { font-size: 1.1rem; }
    .severity-badge {
      display: inline-block;
      padding: 0.15rem 0.6rem;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
    }
    .severity-badge.critical { background: rgba(248,81,73,0.2); color: var(--critical); }
    .severity-badge.high { background: rgba(219,109,40,0.2); color: var(--high); }
    .cve-ids { margin-bottom: 0.5rem; }
    .cve-ids code {
      background: rgba(88,166,255,0.1);
      color: var(--accent);
      padding: 0.1rem 0.4rem;
      border-radius: 4px;
      font-size: 0.85rem;
    }
    .tag {
      background: rgba(63,185,80,0.15);
      color: var(--green);
      padding: 0.1rem 0.5rem;
      border-radius: 4px;
      font-size: 0.85rem;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      background: var(--surface);
      border-radius: 8px;
      overflow: hidden;
    }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }
    th { color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; font-weight: 600; }
    td a { color: var(--accent); text-decoration: none; }
    td a:hover { text-decoration: underline; }
    ul { padding-left: 1.5rem; }
    ul li { margin-bottom: 0.5rem; }
    .trend-box {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.2rem 1.5rem;
    }
    footer {
      text-align: center;
      padding: 2rem 0;
      border-top: 1px solid var(--border);
      color: var(--text-muted);
      font-size: 0.85rem;
    }
    footer a { color: var(--accent); text-decoration: none; }
    @media (max-width: 600px) {
      .container { padding: 1rem; }
      header h1 { font-size: 1.6rem; }
      .stats { grid-template-columns: repeat(2, 1fr); }
      table { font-size: 0.85rem; }
      th, td { padding: 0.5rem; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🛡️ AI <span>Security Digest</span></h1>
      <p class="subtitle">AI-powered software supply chain security intelligence</p>
      <p class="period">📅 ${periodStart} — ${periodEnd} &nbsp;|&nbsp; Generated: ${generatedAt}</p>
    </header>

    <div class="summary-box">${escapeHtml(digest.summary || 'No summary available.')}</div>

    <div class="stats">
      <div class="stat">
        <div class="number accent">${digest.stats?.total || 0}</div>
        <div class="label">Total CVEs</div>
      </div>
      <div class="stat">
        <div class="number critical">${digest.stats?.critical || 0}</div>
        <div class="label">Critical</div>
      </div>
      <div class="stat">
        <div class="number high">${digest.stats?.high || 0}</div>
        <div class="label">High</div>
      </div>
      <div class="stat">
        <div class="number">${digest.stats?.avgScore || 'N/A'}</div>
        <div class="label">Avg CVSS</div>
      </div>
    </div>

    <section>
      <h2>🔥 Key Highlights</h2>
      ${highlightsHtml || '<p style="color:var(--text-muted)">No highlights this week.</p>'}
    </section>

    <section>
      <h2>🔗 Supply Chain Risks</h2>
      ${risksHtml || '<p style="color:var(--text-muted)">No specific supply chain risks identified.</p>'}
    </section>

    ${digest.trendAnalysis ? `
    <section>
      <h2>📈 Trend Analysis</h2>
      <div class="trend-box">${escapeHtml(digest.trendAnalysis)}</div>
    </section>
    ` : ''}

    <section>
      <h2>✅ Recommendations</h2>
      <ul>${recommendationsHtml || '<li>No specific recommendations this week.</li>'}</ul>
    </section>

    <section>
      <h2>📋 Top CVEs This Week</h2>
      <table>
        <thead>
          <tr><th>CVE ID</th><th>CVSS</th><th>Vector</th><th>Description</th></tr>
        </thead>
        <tbody>
          ${topCVEsHtml || '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No CVEs this week</td></tr>'}
        </tbody>
      </table>
    </section>

    <footer>
      <p>Powered by <a href="https://nvd.nist.gov/">NVD</a> data &amp; <a href="https://docs.github.com/en/github-models">GitHub Models</a> AI analysis</p>
      <p style="margin-top:0.5rem">
        <a href="https://github.com/tysoncung/ai-security-digest">View Source</a> · 
        Built with <a href="https://github.com/1712n/product-kit-template">Product Kit Template</a>
      </p>
    </footer>
  </div>
</body>
</html>`

  await mkdir("docs", { recursive: true })
  await writeFile("docs/index.html", html)
  console.log("Site built: docs/index.html")
}

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

buildSite().catch(err => {
  console.error("Build failed:", err.message)
  process.exit(1)
})
