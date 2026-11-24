# Deployment Dash Intelligence

A polished, read-only Kubernetes deployment risk analysis application. It helps engineers inspect workload manifests before release, understand configuration and security risks, and prioritize remediation.

## Product goals

- Analyze Kubernetes YAML before a workload is released.
- Detect explainable configuration and container-security risks.
- Show a transparent 0–100 risk score and severity breakdown.
- Give actionable recommendations tied to manifest paths.
- Keep analysis advisory and read-only; never mutate a cluster.

## Current capabilities

- Browser-based YAML upload and editing.
- Multi-document YAML parsing.
- Checks for replica count, CPU/memory requests, memory limits, image tag pinning, readiness/liveness probes, privileged mode, privilege escalation, non-root execution, and host networking.
- Finding severity, evidence path, and recommendation.
- Optional FastAPI analysis endpoint.
- Responsive React and TypeScript interface.
- GitHub Actions workflows for backend quality checks, frontend deployment, and optional Kubescape PR scanning.
- Local import of Kubescape SARIF JSON reports into the dashboard.

## Architecture

| Layer | Technology | Responsibility |
|---|---|---|
| Frontend | React, TypeScript, Vite | Manifest editor, analysis results, responsive UI |
| Browser analysis | TypeScript, js-yaml | Fast local deterministic checks; no cluster credentials |
| API | Python, FastAPI, PyYAML | Versioned analysis endpoint |
| Quality | pytest, Ruff, GitHub Actions | Automated checks |
| Hosting | GitHub Pages | Public static frontend |

The browser runs deterministic checks locally by default, so the public demo can work without a hosted API or Kubernetes credentials. The FastAPI endpoint is available for API-backed integration.

## Run locally

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Backend API

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
uvicorn app.main:app --reload
```

API health: `GET /healthz`

Analyze a manifest: `POST /api/v1/analyze`

Interactive API documentation: `/docs` while the API is running.


## Kubescape GitHub pull-request review

The `.github/workflows/kubescape-review.yml` workflow runs Kubescape against repository configuration when a pull request or push changes Kubernetes YAML, Helm chart metadata, or Kustomize files. It evaluates the NSA and MITRE frameworks, publishes SARIF to GitHub Code Scanning, and keeps a downloadable SARIF artifact for 14 days.

No Kubernetes cluster credentials or Kubescape cloud account are required for this manifest-only workflow. The scan is advisory in this first iteration: the Kubescape step is allowed to complete with findings so teams can evaluate signal quality before enabling merge-blocking policy.

### View Kubescape results in Deployment Dash

1. Open the repository's **Actions** tab and select the **Deployment Dash — Kubescape review** run.
2. Download the `kubescape-sarif-report` artifact and extract it.
3. Open Deployment Dash and choose **Upload YAML / SARIF**.
4. Select `kubescape-results.sarif` (or its JSON report file).
5. Review the imported findings. Severity and score in the dashboard are display mappings; they are not Kubescape's compliance score.

GitHub Code Scanning results are also available in the repository's **Security → Code scanning** area when that feature is enabled for the repository.

The web dashboard does not currently connect to GitHub or fetch reports automatically. Import is a deliberate local file action, keeping repository data under the user's control.

## Risk scoring

The score is the capped sum of explicit rule weights. Severity and recommendations come from deterministic rules, not an LLM. It is an advisory prioritization signal, not a probability of outage or a compliance certification.

## Safety and limitations

- No cluster connection or cluster credentials are required for browser analysis.
- The app does not deploy, patch, restart, or otherwise modify Kubernetes resources.
- Findings are based on submitted manifests only; they do not inspect live cluster state, admission policies, image contents, or runtime behavior.
- A missing probe is a prompt for review, not proof that an application is unhealthy.
- Scores are heuristic and should not be interpreted as calibrated risk probabilities.
- Do not upload secrets or production credentials.
- Validate recommendations against workload requirements before applying changes.

## Development status

This is an actively developed MVP. Verify the latest GitHub Actions runs and the Pages deployment before treating the public demo as live and fully tested.
