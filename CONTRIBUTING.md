# Contributing

Thanks for helping. A few rules keep a security tool trustworthy:

- **Security first.** Anything that touches authentication, the vault, remediation or the update chain
  needs a test and a second reviewer.
- **Read-only by default.** New drivers start with inventory and health; write actions (update,
  quarantine) go through `remediation.execute` and need approval.
- **No secrets in code, tests, logs or screenshots.** Use the vault; redact in logs.
- **Pin dependencies** (Python, npm, base images) and keep images minimal.
- **Device drivers:** one module in `backend/app/drivers/`, documented in `docs/DEVICES.md`, tested
  against a real device or a lab container.

## Development

```bash
cp .env.example .env            # fill in
docker compose up -d --build    # https://localhost
docker compose --profile lab up -d lab-linux   # optional Linux test host
```

Frontend: Angular 21 + Clarity 18 (`frontend/`); build inside `node:24-alpine`. Backend: Python 3.14,
FastAPI (`backend/`).

By contributing you agree that your contribution is licensed under the AGPL-3.0.
