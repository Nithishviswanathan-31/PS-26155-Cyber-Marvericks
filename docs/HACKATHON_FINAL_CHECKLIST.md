# Final Hackathon Checklist

- [ ] Backend starts
- [ ] Frontend starts
- [ ] `/health` works
- [ ] OpenAPI works
- [ ] Demo reset works
- [ ] Cisco analysis works
- [ ] Evidence opens
- [ ] Remediation appears
- [ ] Simulation works
- [ ] Original result remains unchanged
- [ ] PDF works
- [ ] AstraNet UNKNOWN works
- [ ] Suggestion works
- [ ] Approval works
- [ ] Mapping v1 appears
- [ ] Explicit re-analysis works
- [ ] Recognized state appears
- [ ] Adaptive evidence works
- [ ] Re-analysis PDF works
- [ ] No unsafe device execution exists
- [ ] Demo uses synthetic/local data

## Startup

```bash
python -m pip install -r backend/requirements.txt
PYTHONPATH=backend python -m uvicorn app.main:app --app-dir backend --reload --port 8000
cd frontend && npm install && npm run dev
```

## Recovery

- Backend failure: restart with the command above and verify `/health`.
- Frontend failure: verify backend health, then reload the Vite page.
- Suggestion failure: state that the candidate adapter is unavailable; the deterministic path remains independent.
- Re-analysis failure: do not present a recognized result; show the structured error.
- PDF failure: continue the core demo with JSON results/evidence.
- Browser issue: use `HACKATHON_BACKUP_DEMO.md` and `/docs`.

## Safety confirmation

The demo uses only local synthetic files. AI suggestions require human approval,
compliance results are deterministic, remediation is simulation-only, and no
production device is contacted or modified.
