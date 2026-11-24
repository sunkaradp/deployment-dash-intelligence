# Public Release Checklist

A public release is blocked until every required item below is verified. A checked-in checklist is not evidence that a control has passed.

## Ownership and licensing

- [ ] Confirm the maintainer has the right to publish all source, assets, names, and documentation.
- [ ] Check employer, university, internship, thesis, and third-party ownership obligations.
- [x] Select and add Apache License 2.0 (ownership review is still required).
- [ ] Review dependency licenses and third-party notices.
- [ ] Confirm the public repository contains no private thesis or employer material.

## Source and history security

- [ ] Scan every reachable Git commit for secrets, including deleted files.
- [ ] Rotate any credential that was ever exposed; history cleanup alone is insufficient.
- [ ] Review author metadata and remove personal information that should not be public, where feasible.
- [ ] Review all tracked files, examples, screenshots, test fixtures, and generated artifacts.
- [ ] Confirm no real kubeconfig, token, private key, customer manifest, or internal endpoint is present.

## Application security

- [x] Add a 1 MB browser input/file limit and a 100-document YAML limit (verify in CI).
- [x] Add YAML alias/depth protections and adversarial backend tests (verify in CI).
- [ ] Confirm no manifest content is transmitted to third parties.
- [ ] Validate SARIF structure and bound result counts and rendered strings.
- [ ] Review all React rendering paths for HTML injection and unsafe URL handling.
- [ ] Keep the API private until authentication, rate limiting, timeouts, and abuse controls are implemented.
- [ ] Add tests for malformed, oversized, deeply nested, and multi-document inputs.

## Supply chain and CI

- [ ] Pin every third-party GitHub Action to a reviewed full commit SHA (several are pinned; verify all actions and their provenance).
- [ ] Replace mutable action references such as @main.
- [ ] Add dependency lockfiles and use reproducible installs in CI.
- [ ] Enable dependency update automation and vulnerability alerts.
- [ ] Enable secret scanning and push protection where available.
- [ ] Add CodeQL or an equivalent static analysis workflow where applicable.
- [ ] Review workflow permissions and untrusted pull-request behavior.
- [ ] Verify the latest CI, Pages, and Kubescape runs.

## Public documentation and demo

- [ ] Publish SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, and THREAT_MODEL.md.
- [ ] Document product limitations and safe sample inputs.
- [ ] Provide setup, architecture, API, and troubleshooting instructions.
- [ ] Verify the public demo and all links on desktop and mobile.
- [ ] Add a clear privacy/data-handling statement.
- [ ] Add sitemap.xml, robots.txt, canonical URL, and accurate metadata.
- [ ] Submit the sitemap through Google Search Console and Bing Webmaster Tools after launch.

## Release approval

- [ ] All high and critical findings are fixed or explicitly accepted with documented rationale.
- [ ] Independent reviewer has reviewed the release candidate.
- [ ] Create a versioned release and changelog.
- [ ] Re-run the complete checklist against the exact release commit.

**Current status:** NOT READY. Apache licensing and initial parser/input limits have been added, but ownership review, dependency lockfiles, full action pin review, secret-history scanning, API privacy controls, and independent verification remain outstanding.
