# Product Limitations

Deployment Dash Intelligence is an early-stage, manifest-focused advisory tool.

## What it does

- Performs deterministic checks against supported Kubernetes workload manifests.\n- Rejects duplicate YAML mapping keys and bounds input size, document count, alias count, nesting depth, and finding count.
- Reviews selected configuration and container security-context settings.
- Imports local Kubescape SARIF/JSON reports for display.
- Produces explainable findings with evidence paths and recommendations.

## What it does not do

- Connect to, authenticate with, or inspect a live Kubernetes cluster.
- Resolve effective settings from admission controllers, policies, mutating webhooks, defaults, or runtime configuration.
- Inspect container image contents, packages, signatures, provenance, or vulnerabilities.
- Observe runtime behavior, network traffic, node configuration, RBAC permissions, or cloud IAM.
- Prove exploitability, predict outages, or calculate a statistically calibrated probability of risk.
- Certify compliance with a framework or replace a professional security assessment.
- Apply, patch, deploy, restart, or otherwise mutate Kubernetes resources.
- Automatically fetch reports from GitHub.

## Interpreting findings and scores

A finding means that a specific manifest pattern matched a rule. It does not automatically mean that a workload is exploitable or unsafe in its actual environment. Missing configuration may be supplied by cluster defaults or may be inappropriate to enforce for a particular workload.

The 0–100 score is a capped sum of rule weights. It is a prioritization aid only; it is not a probability, benchmark, compliance score, or guarantee. Validate each recommendation against application requirements, platform policy, and the target cluster.

## Input handling

Do not upload secrets, kubeconfigs, tokens, private keys, customer manifests, or production data to a public demo. Prefer synthetic examples. Treat SARIF reports as potentially sensitive because they can contain repository paths and infrastructure details.

## API deployment warning

The optional FastAPI endpoint currently has no authentication, authorization, rate limiting, or tenant isolation. Run it only in a trusted local or private environment. Do not expose it to the public internet until it has been separately hardened and reviewed.
