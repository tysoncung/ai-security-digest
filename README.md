# 🛡️ AI Security Digest

**AI-powered weekly software supply chain security intelligence briefs.**

> [**Live Site →**](https://tysoncung.github.io/ai-security-digest/)

AI Security Digest automatically monitors the [National Vulnerability Database (NVD)](https://nvd.nist.gov/) for critical and high-severity CVEs, then uses [GitHub Models](https://docs.github.com/en/github-models) to generate actionable intelligence briefs focused on **software supply chain security**.

![GitHub Pages](https://img.shields.io/badge/Deployed-GitHub%20Pages-blue)
![Weekly Updates](https://img.shields.io/badge/Updates-Weekly-green)

## What It Does

Every Sunday, a GitHub Actions workflow:

1. **Fetches** the latest critical and high-severity CVEs from the NVD API
2. **Analyzes** them using GitHub Models (GPT-4o-mini) to identify supply chain risks
3. **Generates** an intelligence brief with highlights, risk assessments, and recommendations
4. **Publishes** a clean, dark-themed dashboard to GitHub Pages

## Key Features

- **Supply Chain Focus** — AI analysis specifically targets dependency risks, package vulnerabilities, build system issues, and CI/CD pipeline threats
- **Automated Pipeline** — Fully hands-off weekly updates via GitHub Actions
- **AI-Powered Analysis** — Uses GitHub Models to synthesize raw CVE data into actionable insights
- **Executive Summary** — Quick-glance overview with key stats and trends
- **Zero Dependencies** — Pure Node.js with no external packages (except GitHub Models API)

## How It Differs From the Template

This project significantly departs from the [Product Kit Template](https://github.com/1712n/product-kit-template):

| Template | AI Security Digest |
|----------|-------------------|
| CPW API (RapidAPI) | NVD API (free, no key needed) |
| Generic event tracking | CVE-specific security monitoring |
| Raw data storage | AI-powered analysis & summarization |
| No frontend | Full GitHub Pages dashboard |
| No AI integration | GitHub Models (GPT-4o-mini) |
| Single data script | 3-stage pipeline (fetch → analyze → build) |

## Setup

1. **Fork this repository**

2. **Add secrets:**
   - `MODELS_TOKEN` — A GitHub token with access to [GitHub Models](https://docs.github.com/en/github-models)

3. **Enable GitHub Pages:**
   - Settings → Pages → Source: GitHub Actions

4. **Run manually** (or wait for Sunday):
   - Actions → "Weekly Security Digest" → Run workflow

## Local Development

```bash
# Fetch latest CVEs
node scripts/fetch-cves.js

# Analyze with AI (requires GITHUB_TOKEN)
GITHUB_TOKEN=your_token node scripts/analyze-cves.js

# Build the site
node scripts/build-site.js
```

## Architecture

```
scripts/
  fetch-cves.js    — Pulls critical & high CVEs from NVD API
  analyze-cves.js  — Sends CVE data to GitHub Models for AI analysis
  build-site.js    — Generates static HTML dashboard from digest

data/
  cves-raw.json    — Raw CVE data from NVD
  digest.json      — AI-generated security digest

docs/
  index.html       — GitHub Pages site
```

## Data Sources

- **[NVD API v2.0](https://nvd.nist.gov/developers/vulnerabilities)** — Official NIST vulnerability database
- **[GitHub Models](https://docs.github.com/en/github-models)** — AI analysis via GPT-4o-mini

## License

MIT

---

Built with the [Product Development Kit](https://github.com/1712n/product-kit-template) template.
