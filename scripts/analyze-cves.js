import { readFile, writeFile, mkdir } from "fs/promises"

const GITHUB_TOKEN = process.env.GITHUB_TOKEN
const MODEL = "gpt-4o-mini"
const ENDPOINT = "https://models.inference.ai.azure.com"

if (!GITHUB_TOKEN) {
  console.error("Error: GITHUB_TOKEN is required for GitHub Models")
  process.exit(1)
}

/**
 * Call GitHub Models API (OpenAI-compatible endpoint)
 */
async function callModel(systemPrompt, userPrompt) {
  const response = await fetch(`${ENDPOINT}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${GITHUB_TOKEN}`
    },
    body: JSON.stringify({
      model: MODEL,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt }
      ],
      temperature: 0.3,
      max_tokens: 4000
    })
  })

  if (!response.ok) {
    const text = await response.text()
    throw new Error(`GitHub Models API failed: ${response.status} - ${text}`)
  }

  const data = await response.json()
  return data.choices[0].message.content
}

/**
 * Analyze CVEs and generate a security intelligence brief
 */
async function analyzeCVEs() {
  let rawData
  try {
    rawData = JSON.parse(await readFile("data/cves-raw.json", "utf-8"))
  } catch {
    console.error("No CVE data found. Run 'npm run fetch' first.")
    process.exit(1)
  }

  const cves = rawData.cves
  if (cves.length === 0) {
    console.log("No CVEs to analyze")
    await writeFile("data/digest.json", JSON.stringify({
      generatedAt: new Date().toISOString(),
      period: rawData.period,
      summary: "No critical or high severity CVEs were published this week.",
      highlights: [],
      supplyChainRisks: [],
      recommendations: [],
      stats: { total: 0, critical: 0, high: 0 }
    }, null, 2))
    return
  }

  console.log(`Analyzing ${cves.length} CVEs with GitHub Models (${MODEL})...`)

  // Prepare CVE summaries for the model
  const cveList = cves.slice(0, 40).map(c => 
    `- ${c.id} (CVSS ${c.score} ${c.severity}): ${c.description.substring(0, 200)}`
  ).join("\n")

  const systemPrompt = `You are a cybersecurity analyst specializing in software supply chain security. 
You produce concise, actionable weekly intelligence briefs for security teams.
Always respond in valid JSON format.`

  const userPrompt = `Analyze these CVEs published in the last week and produce a security intelligence digest.
Focus on software supply chain implications (dependency risks, package vulnerabilities, build system issues, CI/CD risks).

CVEs:
${cveList}

Respond with this exact JSON structure:
{
  "summary": "2-3 sentence executive summary of the week's security landscape",
  "highlights": [
    {
      "title": "Brief title",
      "cveIds": ["CVE-XXXX-XXXXX"],
      "severity": "CRITICAL or HIGH",
      "impact": "What this means for organizations",
      "supplyChainRelevance": "How this relates to supply chain security"
    }
  ],
  "supplyChainRisks": [
    {
      "risk": "Specific supply chain risk identified",
      "affectedArea": "e.g., npm packages, container images, CI pipelines",
      "mitigation": "Recommended action"
    }
  ],
  "trendAnalysis": "Brief analysis of trends seen this week",
  "recommendations": ["Actionable recommendation 1", "Actionable recommendation 2"]
}

Include 3-5 highlights and 2-4 supply chain risks. Be specific and actionable.`

  const analysis = await callModel(systemPrompt, userPrompt)
  
  // Parse the AI response
  let parsed
  try {
    // Try to extract JSON from the response (handle markdown code blocks)
    const jsonMatch = analysis.match(/\{[\s\S]*\}/)
    parsed = JSON.parse(jsonMatch ? jsonMatch[0] : analysis)
  } catch {
    console.error("Failed to parse AI response, using raw text")
    parsed = {
      summary: analysis,
      highlights: [],
      supplyChainRisks: [],
      recommendations: []
    }
  }

  const digest = {
    generatedAt: new Date().toISOString(),
    period: rawData.period,
    model: MODEL,
    stats: {
      total: cves.length,
      critical: cves.filter(c => c.severity === "CRITICAL").length,
      high: cves.filter(c => c.severity === "HIGH").length,
      avgScore: +(cves.reduce((s, c) => s + c.score, 0) / cves.length).toFixed(1)
    },
    ...parsed,
    topCVEs: cves.slice(0, 10).map(c => ({
      id: c.id,
      score: c.score,
      severity: c.severity,
      description: c.description.substring(0, 300),
      attackVector: c.attackVector,
      references: c.references
    }))
  }

  await mkdir("data", { recursive: true })
  await writeFile("data/digest.json", JSON.stringify(digest, null, 2))
  console.log("Security digest generated: data/digest.json")
}

analyzeCVEs().catch(err => {
  console.error("Analysis failed:", err.message)
  process.exit(1)
})
