# Release Readiness Evidence Review

**Review date:** 2026-11-25  
**Repository:** `sunkaradp/deployment-dash-intelligence`  
**Decision:** Not ready for a versioned public release.

This document records repository evidence and remaining verification. It is not an independent audit, legal opinion, or certification.

## Evidence observed

- The repository contains an Apache License 2.0 text file.
- `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `THREAT_MODEL.md`, and `docs/LIMITATIONS.md` are present.
- Current GitHub Actions workflow files inspected use full commit SHAs for third-party `uses:` references. This must be rechecked when workflows change.
- The README's composite Action example now uses an immutable commit SHA rather than `@main`.
- The browser entry file has no direct `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, or `sendBeacon` calls at the time of review.
- A Node regression test was added for common browser network APIs and a direct form action. It is a narrow static guard, not proof of runtime privacy.
- SARIF import has explicit limits for runs, rules, results, and selected text fields.
- The optional FastAPI service remains unauthenticated and rate-unlimited; it must stay private/local.
- The browser privacy regression was merged in [PR #11](https://github.com/sunkaradp/deployment-dash-intelligence/pull/11) at commit [`7c56056a27fe6c772a33948dccd16c92ce23cdd6`](https://github.com/sunkaradp/deployment-dash-intelligence/commit/7c56056a27fe6c772a33948dccd16c92ce23cdd6). The eight successful check runs for that exact commit are individually verifiable: [CodeQL](https://github.com/sunkaradp/deployment-dash-intelligence/runs/138901726365), [Sourcery review](https://github.com/sunkaradp/deployment-dash-intelligence/runs/138901475503), [Action smoke](https://github.com/sunkaradp/deployment-dash-intelligence/actions/runs/45523632389), [frontend](https://github.com/sunkaradp/deployment-dash-intelligence/actions/runs/45523632171), [secret scanning](https://github.com/sunkaradp/deployment-dash-intelligence/actions/runs/45523632125), [Python analysis](https://github.com/sunkaradp/deployment-dash-intelligence/actions/runs/45523632144), [Python tests](https://github.com/sunkaradp/deployment-dash-intelligence/actions/runs/45523632171), and [TypeScript/Python parity](https://github.com/sunkaradp/deployment-dash-intelligence/actions/runs/45523632144).
- The secret-scanning workflow now attempts to upload the redacted Gitleaks SARIF output as a 30-day workflow artifact even after a failed scan step. If Gitleaks fails before creating the report, no artifact can be uploaded; verify artifact availability and manually triage it on a run after this workflow change. Earlier runs did not retain this artifact.
- The Action smoke workflow now supports `workflow_dispatch`, allowing a maintainer to select the exact candidate branch or tag and run the smoke test even when path filters would otherwise skip it. A successful run on the actual release candidate is still required.

## Important limitations of this review

### Reproducibility

No `frontend/package-lock.json` was present when inspected. Frontend workflows use `npm install`, not `npm ci`. Python dependencies are specified as version ranges in `pyproject.toml` and there is no reviewed hash-locked Python environment file. Reproducible dependency installation is therefore not established.

The current execution environment could not reach GitHub or the npm registry to generate and validate genuine lockfiles. No synthetic lockfile was created.

### Dependency licensing

The manifests identify direct dependencies, but without a resolved lockfile and a complete transitive dependency inventory, this review cannot establish the licenses of every shipped package. Generate inventories from resolved dependencies and review unknown/dual-license packages before release.

### Browser privacy

Static inspection of the browser entry point found no direct use of common network APIs, and the page stylesheet did not contain external CSS imports or URL references in the inspected file. This is not a complete network audit: transitive packages, browser runtime behavior, hosting resources, and future changes must be checked in DevTools using synthetic canary values. Do not use production secrets for this test.

### Git history and secrets

The repository has a Gitleaks workflow configured to scan reachable Git history and now retain its redacted SARIF report as a workflow artifact for 30 days. The artifact is available only after a run using the updated workflow. A successful workflow is evidence that the scanner completed, not proof that every possible secret was detected or that all findings were manually triaged. Download and review the report, check all reachable refs, and rotate any exposed credential. Never reproduce secret values in this document.

### Ownership and legal review

The Apache-2.0 license file does not prove the maintainer owns or has permission to publish every source file, asset, screenshot, name, or document. Review employer, internship, university, thesis, contractor, and third-party obligations. This project has not received legal clearance through this engineering review.

### Independent security review

No independent reviewer has been engaged or completed a review in this process. A maintainer self-review is not independent assurance.

## Release decision

Do not create a v1.0 tag or claim production readiness until:
1. npm and Python dependencies are locked and clean installs pass in CI;
2. direct and transitive dependency licenses and notices are reviewed;
3. browser network behavior is manually inspected against synthetic canary values;
4. Gitleaks findings and repository history are manually reviewed using a retained report from the updated workflow;
5. ownership and publication rights are confirmed;
6. an independent security review is completed and findings are resolved or explicitly accepted;
7. all GitHub Actions and deployment checks pass on the exact release candidate, including a manually dispatched Action smoke run for that candidate.
