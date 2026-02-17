import { writeFile, mkdir, readFile } from "fs/promises"

const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

/**
 * Fetch recent CVEs from NVD (National Vulnerability Database)
 * Focuses on high/critical severity supply chain related vulnerabilities
 */
function getDateRange(days = 7) {
  const end = new Date()
  const start = new Date()
  start.setDate(start.getDate() - days)
  return {
    start: start.toISOString().split(".")[0] + ".000",
    end: end.toISOString().split(".")[0] + ".000"
  }
}

async function fetchCVEs() {
  const { start, end } = getDateRange(7)
  
  console.log(`Fetching CVEs from ${start} to ${end}`)

  // Fetch critical and high severity CVEs
  const params = new URLSearchParams({
    pubStartDate: start,
    pubEndDate: end,
    cvssV3Severity: "CRITICAL",
    resultsPerPage: "50"
  })

  const response = await fetch(`${NVD_API}?${params}`, {
    headers: { "User-Agent": "AI-Security-Digest/1.0" }
  })

  if (!response.ok) {
    throw new Error(`NVD API request failed: ${response.status}`)
  }

  const data = await response.json()
  const cves = (data.vulnerabilities || []).map(v => {
    const cve = v.cve
    const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || {}
    const cvssData = metrics.cvssData || {}
    
    return {
      id: cve.id,
      published: cve.published,
      lastModified: cve.lastModified,
      description: (cve.descriptions || []).find(d => d.lang === "en")?.value || "",
      severity: cvssData.baseSeverity || "UNKNOWN",
      score: cvssData.baseScore || 0,
      attackVector: cvssData.attackVector || "UNKNOWN",
      references: (cve.references || []).map(r => ({ url: r.url, source: r.source })).slice(0, 3),
      weaknesses: (cve.weaknesses || []).flatMap(w => w.description?.map(d => d.value) || [])
    }
  })

  // Sort by score descending
  cves.sort((a, b) => b.score - a.score)

  console.log(`Found ${cves.length} critical CVEs`)

  // Also fetch HIGH severity
  const highParams = new URLSearchParams({
    pubStartDate: start,
    pubEndDate: end,
    cvssV3Severity: "HIGH",
    resultsPerPage: "50"
  })

  // Rate limit: NVD allows 5 requests per 30 seconds without API key
  await new Promise(r => setTimeout(r, 6500))

  const highResponse = await fetch(`${NVD_API}?${highParams}`, {
    headers: { "User-Agent": "AI-Security-Digest/1.0" }
  })

  let highCves = []
  if (highResponse.ok) {
    const highData = await highResponse.json()
    highCves = (highData.vulnerabilities || []).map(v => {
      const cve = v.cve
      const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || {}
      const cvssData = metrics.cvssData || {}
      return {
        id: cve.id,
        published: cve.published,
        lastModified: cve.lastModified,
        description: (cve.descriptions || []).find(d => d.lang === "en")?.value || "",
        severity: cvssData.baseSeverity || "HIGH",
        score: cvssData.baseScore || 0,
        attackVector: cvssData.attackVector || "UNKNOWN",
        references: (cve.references || []).map(r => ({ url: r.url, source: r.source })).slice(0, 3),
        weaknesses: (cve.weaknesses || []).flatMap(w => w.description?.map(d => d.value) || [])
      }
    })
    highCves.sort((a, b) => b.score - a.score)
    console.log(`Found ${highCves.length} high severity CVEs`)
  }

  const allCves = [...cves, ...highCves]
  
  await mkdir("data", { recursive: true })
  await writeFile("data/cves-raw.json", JSON.stringify({
    fetchedAt: new Date().toISOString(),
    period: { start, end },
    totalCritical: cves.length,
    totalHigh: highCves.length,
    cves: allCves
  }, null, 2))

  console.log(`Saved ${allCves.length} CVEs to data/cves-raw.json`)
  return allCves
}

fetchCVEs().catch(err => {
  console.error("Fetch failed:", err.message)
  process.exit(1)
})
