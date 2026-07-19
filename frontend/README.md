 🛡️ ShieldLabs — AI Security Command Center

> **From scattered vulnerability alerts to prioritized attack paths and remediation pull requests.**

ShieldLabs is a hackathon-built security platform that scans source code and live web attack surface, reasons about real-world exploitability with AI, connects findings into cross-domain attack chains, and helps developers ship fixes through validated Auto-PRs.

It is designed for teams who do not just want a list of vulnerabilities — they want to know **what can actually be exploited first, why it matters, and how to fix it fast**.

---

🚀 The 30-second pitch

Most security scanners overwhelm developers with isolated findings. ShieldLabs turns those findings into a decision-ready workflow:

1. **Scan code** for insecure patterns and framework-level weaknesses.
2. **Scan web targets** for exposed services, misconfigurations, weak headers, SSL/TLS issues, exposed files, Nuclei findings, and optional consent-based SQLMap checks.
3. **Score exploitability** with AI-assisted CVSS reasoning.
4. **Connect vulnerabilities** into cross-domain attack chains that show how code bugs and exposed web assets compound.
5. **Generate fixes** using deterministic patches, LLM proposals, and static remediation guides.
6. **Open remediation PRs** only after local validation checks pass.

> **Core differentiator:** ShieldLabs does not stop at detection. It moves from **finding → reasoning → prioritization → remediation → pull request**.

---

✨ Why judges should care

🔥 A better security story than “we found bugs”

Traditional scanners answer: **“What is wrong?”**

ShieldLabs answers:

- **What is wrong?**
- **How exploitable is it?**
- **Which issues combine into a real attack path?**
- **What should be fixed first?**
- **Can we safely create a PR for the fix?**

### 🧠 AI where it actually helps

ShieldLabs uses AI for the high-context decisions that static tools struggle with:

- Exploitability reasoning
- CVSS scoring support
- Cross-domain attack-chain analysis
- Developer-friendly fix explanations
- Bounded remediation proposals

### 🧩 End-to-end workflow

A polished demo can show the full loop in minutes:

```text
GitHub repo + domain
        ↓
Code scan + web scan
        ↓
AI CVSS severity reasoning
        ↓
Attack-chain correlation
        ↓
Fix suggestions
        ↓
Validated Auto-PR
```

---

## 🧭 Product workflow

### 1. Choose a scan profile

ShieldLabs supports three scan modes:

| Mode | Purpose | Best demo use |
| --- | --- | --- |
| **Code Scan** | Finds vulnerabilities in a GitHub repository | Show SAST + fix generation |
| **Web Scan** | Checks a live domain or IP | Show external attack surface |
| **Combined Scan** | Runs code + web + attack-chain analysis | **Best hackathon demo path** |

### 2. Run passive-first reconnaissance

Passive web scanning is the safe default. It can identify:

- Open ports
- Exposed databases/services
- Exposed sensitive files such as `.env`, `.git`, backups, config files, and dependency manifests
- Missing security headers
- SSL/TLS misconfigurations
- Nuclei template findings when Nuclei is installed

### 3. Optionally enable active payload mode

Active mode is intentionally gated behind explicit consent. When enabled, ShieldLabs can run SQLMap against user-provided URLs with query parameters to confirm SQL injection.

> Active testing sends real payloads. Only use it on systems you own or have written permission to test.

### 4. Watch live scan telemetry

The frontend polls backend progress and displays:

- Current pipeline stage
- Percentage complete
- Live severity counters
- Success/failure state
- Human-readable scan status

### 5. Review the security intelligence report

The results page provides:

- Executive risk summary
- Severity distribution chart
- CVSS scores
- Search, filter, and sorting controls
- Fixable-only and attack-chain-only views
- Expandable finding cards
- Attack-chain cards with evidence, impact, reasoning, and recommended fix order

### 6. Create an Auto-Fix Pull Request

For eligible code findings, ShieldLabs can:

- Select fixable findings
- Apply generated fixes
- Run patch-level validation
- Run local test policy where available
- Create a GitHub branch and pull request
- Report applied fixes, skipped fixes, and validation details

---

## 🧰 Feature matrix

| Category | Features |
| --- | --- |
| **Backend API** | FastAPI scan endpoints, status polling, results retrieval, Auto-PR endpoint, health checks |
| **Code security** | Bandit integration, hardcoded secret detection, weak JWT checks, XSS patterns, CSRF checks, missing security headers, missing rate limiting, unvalidated redirects |
| **Web security** | Port scan orchestration, exposed file checks, SSL/TLS analysis, security header checks, optional Nuclei, consent-based SQLMap |
| **AI reasoning** | Groq-backed exploitability assessment, CVSS scoring, cross-domain attack-chain generation |
| **Remediation** | Static guides, deterministic fixes, LLM-generated bounded fixes, remediation status tracking, patch provenance |
| **Auto-PR** | GitHub integration, eligible-finding filtering, local validation, manual-review fallback, PR creation |
| **Frontend** | Cyber command UI, scan setup, active-scan consent panel, live progress, findings dashboard, charts, attack-chain visualization, Auto-PR panel |
| **Persistence** | SQLite/SQLAlchemy models for scans, findings, reports, and attack chains |
| **Testing** | Pytest coverage for scanner logic, deterministic fixes, SQLMap runner, cross-domain analysis, patch provenance, Auto-PR validation, and pipeline behavior |

---

## 🏗️ Architecture

```text
frontend/ React + Vite
  ├─ Scan console
  ├─ Live progress UI
  ├─ Results dashboard
  ├─ Attack-chain visualization
  └─ Auto-PR panel

backend/ FastAPI
  ├─ API routes
  ├─ Scan pipeline orchestrator
  ├─ Code scanners
  ├─ Web scanners
  ├─ AI severity + attack-chain agents
  ├─ Fix generation agents
  ├─ Auto-PR engine
  └─ SQLite persistence
```

---

## 📁 Repository structure

```text
.
├── backend/
│   ├── app/
│   │   ├── api/                 # FastAPI routes
│   │   ├── agents/              # AI reasoning, fix generation, Auto-PR
│   │   ├── scanners/            # Code and web security scanners
│   │   ├── utils/               # LLM, repo, logging, rate limit helpers
│   │   ├── database.py          # SQLAlchemy models and migrations
│   │   ├── pipeline.py          # End-to-end scan orchestration
│   │   └── schemas.py           # Pydantic API contracts
│   ├── requirements.txt
│   └── test_*.py                # Backend tests
├── frontend/
│   ├── src/
│   │   ├── api/                 # Axios client
│   │   ├── components/          # Reusable UI components
│   │   ├── pages/               # Home, scan progress, results
│   │   └── utils/               # Severity helpers
│   ├── package.json
│   └── vite.config.js
└── tests/fixtures/              # Vulnerable demo/test apps
```

---

## ⚙️ Local setup

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Optional environment variables:

```bash
GROQ_API_KEY=your_groq_key
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5-coder:7b
NUCLEI_PATH=/path/to/nuclei
SQLMAP_PATH=/path/to/sqlmap.py
SQLMAP_PYTHON=python3
DATABASE_URL=sqlite:///./shieldlabs.db
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The Vite dev server runs on port `3000` and proxies `/api` requests to `http://localhost:8000`.

---

## 🧪 Useful checks

```bash
# Frontend production build
npm --prefix frontend run build

# Focused backend tests
PYTHONPATH=backend pytest -q backend/test_deterministic_fixes.py backend/test_secret_detector.py backend/test_cross_domain_analyzer.py

# Full backend test suite
PYTHONPATH=backend pytest -q backend
```

---

## 🎤 Recommended hackathon demo script

### Step 1 — Open with the pain

> “Security tools flood developers with hundreds of findings. The hard part is knowing which vulnerabilities create an actual attack path and how to fix them safely.”

### Step 2 — Launch a combined scan

Use a vulnerable demo repository and a controlled test domain. Choose **Combined Scan** so judges see the full product.

### Step 3 — Show live telemetry

Point out the scan stages: code detection, web reconnaissance, CVSS scoring, and attack-chain analysis.

### Step 4 — Open the results report

Show:

- Executive risk summary
- Severity counts
- CVSS-ranked findings
- Search/filter controls
- Fixable findings

### Step 5 — Open an attack chain

This is the “wow” moment. Explain how ShieldLabs connects separate findings into an exploitable path and recommends fix order.

### Step 6 — Show Auto-PR

Create or show a prepared remediation PR. Emphasize that the PR is validation-aware and manual-review-friendly.

### Step 7 — Close with the transformation

> “ShieldLabs turns security scanning from noisy detection into prioritized remediation.”

---

## 🏆 Winning narrative

ShieldLabs is not just a vulnerability scanner. It is an **AI security analyst and remediation assistant** for modern development teams.

The platform combines:

- The breadth of automated scanners
- The context of AI reasoning
- The practicality of developer-first remediation
- The clarity of attack-chain prioritization

In a real engineering team, this means less time arguing over scanner noise and more time fixing the vulnerabilities that actually reduce risk.

---

## ⚠️ Prototype limitations

ShieldLabs is hackathon-ready, not production-complete. Current limitations include:

- Custom code rules are strongest for Python/Flask projects.
- Some scanners require local tools such as nmap, Nuclei, and SQLMap.
- AI features require configured Groq/Ollama providers.
- Auto-PR currently uses a GitHub token flow; a production version should use a GitHub App/OAuth installation.
- Active scanning must only be used on authorized targets.

These limitations are intentional tradeoffs for speed, demo clarity, and safety during the hackathon build.

---

## 🛣️ Future roadmap

- Multi-language SAST support for JavaScript/TypeScript, Java, Go, and PHP
- GitHub App installation flow instead of personal access tokens
- SARIF export for GitHub Advanced Security compatibility
- PDF/HTML executive reports
- Container and dependency vulnerability scanning
- Authenticated web scanning
- Team dashboards and historical risk trends
- CI/CD integration for pull-request security gates

---

## ❤️ Built for builders

ShieldLabs exists for developers who want security tooling that is:

- Clear enough for founders
- Useful enough for engineers
- Honest enough for security teams
- Fast enough for hackathons

**Find the risk. Understand the attack path. Ship the fix.**
