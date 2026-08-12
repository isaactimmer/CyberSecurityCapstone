# CyberSecurityCapstone

## Agent skills

### Issue tracker

Issues are tracked as GitHub Issues on `isaactimmer/CyberSecurityCapstone` via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Uses the five canonical triage labels (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout — one `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.

## Running the console

The UI is a FastAPI web app (`server.py`) serving `web/` over a JSON API to the
engine — **not** Streamlit (retired; see `docs/adr/0002-web-console-over-fastapi.md`).

```
.\.venv\Scripts\python.exe -m uvicorn server:app --port 8000   # http://localhost:8000
.\.venv\Scripts\python.exe -m pytest -q                        # tests
```

The front end (`web/app.js`) is a pure renderer — all scoring/packing lives in the
Python engine behind `dashboard.plan_payload`. Runs offline off the cached feeds.
