# Public Release Checklist
A public release is blocked until every required item below is verified against the exact release candidate. A checked-in checklist is not evidence that a control has passed.
## Ownership and licensing
- [ ] Confirm the maintainer has the right to publish all source, assets, names, and documentation.
- [ ] Check employer, university, internship, thesis, and third-party ownership obligations.
- [x] Apache License 2.0 file is present (this does not establish ownership or grant rights to third-party material).
- [ ] Generate complete direct and transitive dependency inventories for npm and Python, including license identifiers and notices.
- [ ] Review dependency licenses and third-party notices; resolve unknown, dual-license, or incompatible license metadata.
- [ ] Confirm the public repository contains no private thesis or employer material.
## Source and history security
- [x] Automated Gitleaks workflow scans reachable Git history on scheduled and repository events.
- [x] Gitleaks workflow attempts to upload its redacted SARIF report as a 30-day workflow artifact even after a failed scan step; verify the artifact exists for the exact run because no artifact is possible if the report was never created.
- [ ] Download and review the latest Gitleaks artifact; investigate every finding and rotate any credential that was ever exposed. A successful scan is not a substitute for manual triage.
- [ ] Review author metadata and remove personal information that should not be public, where feasible.
- [ ] Review all tracked files, examples, screenshots, test fixtures, and generated artifacts.
- [ ] Confirm no real kubeconfig, token, private key, customer manifest, or internal endpoint is present.
## Application security
- [x] Browser input/file size limit and YAML document limit are implemented.
- [x] Backend YAML alias/depth protections and adversarial tests are implemented.
- [x] SARIF run, rule, result, and selected text-field limits are implemented.
- [x] Static regression guard detects common network APIs in the browser entry point.
- [ ] Perform browser DevTools network inspection on the deployed demo with synthetic canary manifest values; confirm no manifest contents leave the browser.
- [ ] Review every React rendering path, imported SARIF field, URL, and file-handling path for unsafe rendering and resource exhaustion.
- [ ] Add adversarial tests for malformed SARIF shapes, deeply nested SARIF, oversized arrays/strings, and browser rendering.
- [ ] Keep the API private until authentication, authorization, rate limiting, timeouts, safe logging, and abuse controls are implemented.
## Supply chain and CI
- [x] Third-party GitHub Actions in current workflow files are pinned to full commit SHAs (re-audit before release).
- [x] Public README composite Action example is pinned to an immutable commit SHA.
- [x] Genuine npm lockfile is committed at frontend/package-lock.json.
- [x] Hash-locked Python dependency files are committed at requirements-prod.lock and requirements-dev.lock.
- [x] CI, Pages, and the composite Action install frontend dependencies using npm ci and the committed npm lockfile.
- [x] CI installs Python development dependencies using --require-hashes and the committed development lockfile.
- [ ] Pin and include all build-time tools used by CI in a reviewed toolchain policy; pip-audit is currently installed at a pinned version separately.
- [ ] Enable and review dependency update automation, vulnerability alerts, and push protection where available.
- [ ] Review workflow permissions, action provenance, shell interpolation, and untrusted pull-request behavior.
- [ ] Verify the latest CI, Pages, CodeQL, secret scanning, Action smoke, and Kubescape runs for the exact release candidate. For Action smoke, use the workflow's workflow_dispatch trigger and select the exact candidate branch or tag; record the resulting run URL.
## Public documentation and demo
- [x] SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, and THREAT_MODEL.md are present.
- [x] Product limitations and private/local API constraints are documented.
- [ ] Verify setup instructions after lockfiles and reproducible installs are added.
- [ ] Verify the public demo and links on desktop and mobile.
- [ ] Add and validate sitemap.xml, robots.txt, canonical URL, and accurate metadata if search indexing is part of the launch plan.
- [ ] Confirm privacy/data-handling statements match observed browser network behavior.
## Independent review and release approval
- [ ] Obtain an independent security review from someone who did not implement the changes.
- [ ] Resolve all high and critical findings or document an explicit, justified risk acceptance.
- [ ] Confirm ownership and licensing review with relevant employer/university/rights holders where applicable.
- [ ] Create a versioned release and changelog only after all required gates pass.
- [ ] Re-run this complete checklist against the exact release commit.
**Current status: NOT READY.** Committed lockfiles are now consumed by CI, Pages, and the composite Action in the reproducible-installs change. Remaining gates include successful clean-install workflow runs, full dependency license inventory, observed browser network verification, manual secret-history review, ownership confirmation, and independent security review.
