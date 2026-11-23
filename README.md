# Deployment Dash Intelligence

An AI-assisted, policy-first Kubernetes deployment risk analysis platform.

## What it does

Deployment Dash Intelligence helps engineers inspect a Kubernetes workload before release, identify configuration and operational risks, and understand why those risks matter.

The first release focuses on **read-only analysis**. It does not deploy, patch, restart, or otherwise mutate a cluster.

## Why it exists

The project complements two separate capabilities:

- **k8s-platform-intelligence** forecasts node memory pressure.
- **k3s-ai-remediation** responds to runtime incidents through constrained remediation workflows.
- **Deployment Dash Intelligence** evaluates deployment changes before rollout.

The goal is to make pre-deployment decisions more explainable and safer—not to add another generic AI dashboard.

## MVP scope

1. Upload or paste Kubernetes YAML manifests.
2. Parse and validate supported workload resources.
3. Run deterministic checks for resource requests/limits, probes, replicas, security context, image pinning, and risky privileges.
4. Produce a transparent risk score with individual findings, severity, evidence, and remediation guidance.
5. Optionally generate a plain-language explanation of the deterministic findings.
6. Keep an analysis history that can be exported as a report.

## Design principles

- Deterministic checks are the source of truth; an LLM cannot change finding severity or approve a deployment.
- Read-only by default. No cluster credentials are needed for offline manifest analysis.
- Never claim production readiness or measured accuracy without reproducible evidence.
- Treat uploaded manifests and annotations as untrusted input.
- Make every finding traceable to a rule and the relevant manifest path.

## Initial architecture

- **API:** Python and FastAPI
- **Analysis engine:** deterministic Python rules
- **Manifest parsing:** Kubernetes YAML parsing with schema-aware validation added incrementally
- **Persistence:** SQLite for local development, with a clean path to PostgreSQL
- **UI:** React and TypeScript
- **AI layer:** optional explanation adapter, isolated from scoring and policy decisions
- **Quality:** unit tests, API tests, linting, type checks, and CI

## Development status

The repository is at project bootstrap. Features will be marked complete only after implementation and tests exist. No cluster integration, benchmark, or production deployment is claimed yet.

## Safety boundary

This project is an advisory analysis tool. It does not replace Kubernetes admission control, policy enforcement, security review, or operational judgement. Do not upload secrets or production credentials.
