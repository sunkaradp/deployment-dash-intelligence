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
- Checks for replica count, CPU/memory requests, memory limits, required container images, image tag pinning, readiness/liveness probes, privileged mode, privilege escalation, non-root execution and UID 0, read-only root filesystems, Linux capabilities, seccomp profiles, host namespaces, host networking, host ports, hostPath volumes, and explicit service-account-token automounting.
- Finding severity, evidence path, and recommendation.
- Optional FastAPI analysis endpoint.
- Responsive React and TypeScript interface.
- GitHub Actions workflows for backend quality checks, frontend deployment, CodeQL analysis, Gitleaks secret scanning, Dependabot updates, and optional Kubescape PR scanning.
- Local import of Kubescape SARIF JSON reports into the dashboard.

## Kubernetes security checks

The built-in rules are deterministic manifest checks, not a full Kubernetes policy engine. They intentionally flag configuration that deserves review, including missing hardening settings. A finding is not automatically proof of exploitability: validate each recommendation against application requirements, cluster defaults, and your admission policy.

The analyzer checks both Pod-level and container-level security-context settings where Kubernetes supports inheritance or overrides. It does not inspect live cluster defaults, service-account configuration, admission policies, image contents, or runtime state.

## Architecture

| Layer | Technology | Responsibility |
|---|---|---|
| Frontend | React, TypeScript, Vite | Manifest editor, analysis results, responsive UI |
| Shared browser/Node rules engine | TypeScript, js-yaml (`frontend/src/analyzer.ts`) | Deterministic manifest checks reusable by the browser and future Node CLI / GitHub Action |
| API | Python, FastAPI, PyYAML | Versioned analysis endpoint |
| Quality | pytest, Ruff, TypeScript, Node test runner, Vite, GitHub Actions | Backend tests/lint, golden analyzer fixtures, type-check and frontend production build |
| Hosting | GitHub Pages | Public static frontend |

The browser runs deterministic checks locally by default, so the public demo works without a hosted API or Kubernetes credentials. The FastAPI endpoint is an optional private/local integration surface and is not part of the public demo. The browser's YAML rules now live in a standalone TypeScript module with golden tests; this is the rules engine intended for reuse by a Node CLI and GitHub Action. The optional Python API still has its own Python implementation, so exact browser/API parity is not claimed yet.

## Run locally

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### CLI and GitHub Action

The CLI and composite GitHub Action use the same TypeScript rules module as the browser analyzer.

Build and run the CLI from `frontend/`:

```bash
npm install
npm run deploydash -- ../path/to/kubernetes/manifests
```

Use `--json` for machine-readable output:

```bash
npm run deploydash -- ../path/to/kubernetes/manifests --json
```

Exit codes: `0` means no findings, `1` means findings were detected, and `2` means an input or analysis error occurred. The CLI scans YAML/JSON files only, with per-file and file-count limits; it does not connect to a cluster or modify files.

Use the composite action after checking out your repository:

```yaml
- uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
- uses: sunkaradp/deployment-dash-intelligence/.github/actions/deploydash@48933bca7a6bdf6a87be49f36a1c61a50e543294
  with:
    path: ./k8s
    fail-on-findings: "true"
```

The action currently runs the read-only scan and fails the step when findings exist. It does not yet post inline pull-request comments or publish SARIF; those are separate follow-up integrations. Pin the action to a reviewed commit SHA in production workflows.

### Backend API

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
uvicorn app.main:app --reload --host 127.0.0.1
```

API health: `GET /healthz`

Analyze a manifest: `POST /api/v1/analyze`

Interactive API documentation: `http://127.0.0.1:8000/docs` while the API is running.

The API is deliberately private/local. Do not bind it to `0.0.0.0` or expose it through a public reverse proxy. If you run the container image, publish the port only on loopback, for example:

```bash
docker build -t deployment-dash-intelligence .
docker run --rm -p 127.0.0.1:8000:8000 deployment-dash-intelligence
```

The API currently has no authentication, authorization, or rate limiting; loopback binding is a deployment precaution, not a substitute for those controls.


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


## Security, privacy, and responsible use

Read these documents before using, contributing to, or deploying the project:

- [Security policy](SECURITY.md) — how to report vulnerabilities privately.
- [Threat model](THREAT_MODEL.md) — assets, trust boundaries, threats, and mitigations.
- [Security architecture](docs/SECURITY-ARCHITECTURE.md) — input handling and deployment boundaries.
- [Product limitations](docs/LIMITATIONS.md) — supported scope and what findings do not prove.
- [Contributing guide](CONTRIBUTING.md) — development and pull request expectations.
- [Code of Conduct](CODE_OF_CONDUCT.md) — community expectations.
- [Public release checklist](docs/RELEASE-CHECKLIST.md) — mandatory release gates.

**Important:** The optional FastAPI endpoint is intended for private/local use only and currently has no authentication, authorization, or rate limiting. Do not expose it to the public internet. Do not upload secrets, kubeconfigs, private keys, customer manifests, or production data to the public demo. The browser workflow is intended to process files locally, but verify network behavior before relying on that property for sensitive data.

## License status

This project is licensed under the [Apache License 2.0](LICENSE).

## Development status

This is an actively developed MVP. Verify the latest GitHub Actions runs and the Pages deployment before treating the public demo as live and fully tested.
