# Contributing

Thanks for considering a contribution to Deployment Dash Intelligence.

## Before opening an issue or pull request

- Read [SECURITY.md](SECURITY.md). Never report vulnerabilities in public issues.
- Do not include secrets, private kubeconfigs, customer manifests, internal endpoints, or personal data.
- Use synthetic examples that are safe to publish.
- For substantial changes, open an issue first to discuss scope and compatibility.

## Development setup

### Backend

Requires Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
ruff check .
pytest
```

### Frontend

Requires a supported Node.js LTS release.

```bash
cd frontend
npm install
npm run build
npm run dev
```

## Pull request expectations

- Explain the problem, design, and user-visible behavior.
- Add or update tests for changed analysis rules and edge cases.
- Keep browser and API analysis behavior aligned where applicable.
- Keep analysis deterministic and read-only; do not add cluster mutation or credential collection.
- Document new checks, assumptions, false-positive risks, and limitations.
- Avoid adding dependencies unless there is a clear need; explain the trade-off.
- Ensure CI passes and review the complete diff for accidental secrets or unrelated files.

## Analysis rule design

Rules should be explainable and include a stable rule ID, severity, evidence path, recommendation, and documented rationale. Avoid treating missing optional configuration as proof of exploitability. Do not describe the aggregate score as a probability, compliance result, or guarantee.

## Licensing

The project is licensed under Apache License 2.0. By intentionally submitting a contribution for inclusion, you agree that it is submitted under the terms of that license, subject to any separate written agreement you may have with the maintainer.
