# P0.7 Frontend Analysis Workflow

The P0.7–P0.14 frontend is the user-facing vertical slice of the emergency demo
MVP. It connects supported configuration uploads to the existing
`POST /api/analyze` endpoint and presents deterministic results with traceable
evidence.

Completed analyses also expose a **Generate PDF Report** action. Re-analysis
cards use **Generate Re-analysis Report**, and the simulation result card uses
**Generate Report**. The browser downloads the authoritative backend PDF;
the frontend does not calculate compliance or construct evidence. The report
keeps configuration-source, approved-mapping, and simulated-remediation
evidence distinct and includes the corresponding safety disclaimers.

## Scope

The connected workflow currently supports:

- Cisco IOS/IOS-XE, FortiGate/FortiOS, Palo Alto/PAN-OS, and fictional AstraNet synthetic demo configuration files (`.conf`, `.cfg`, `.txt`)
- One configuration per analysis
- The existing four YAML controls and their deterministic results
- Evidence opened from a result row
- Session-only dashboard summary state

The AstraNet UNKNOWN-pattern display, P0.10-B candidate review, explicit
P0.10-C re-analysis, P0.12 remediation simulation, and P0.13 PDF export are
included. Foundation-model training, production remediation, authentication,
and bulk upload are intentionally out of scope.

## Frontend flow

1. Select or drag a configuration file into the upload area.
2. Review the filename and size.
3. Select **Analyze Configuration**.
4. The typed API client sends the file in `FormData` to `POST /api/analyze`.
5. The page renders vendor/device metadata and the control result table.
6. Select a result row to open its evidence detail dialog.

For an AstraNet analysis, the page also shows the raw UNKNOWN pattern and a
controlled candidate-review panel. The reviewer can request the local demo
suggestion, inspect or correct its proposed properties, enter a demo reviewer
identity, and explicitly approve or reject it. The panel displays the stored
mapping version and the unchanged compliance status. After approval, the
reviewer can explicitly request re-analysis; approval itself never triggers it.
The page then displays the child analysis, mapping version, recognized state,
deterministic results, and mapping-aware evidence.

For the live AstraNet demonstration, the page includes a compact status
timeline: Detected → UNKNOWN → Suggestion Generated → Human Approved → Mapping
Activated → Re-analysis Requested → Recognized → Compliance Evaluated → Evidence
Generated. A safety notice identifies the data as synthetic, states that no
production device is modified, requires human approval for suggestions, and
identifies results as deterministic.

The page keeps the explicit states `IDLE`, `FILE_SELECTED`, `UPLOADING`,
`SUCCESS`, and `ERROR`. Duplicate submissions are disabled while the request is
in progress.

## API client contract

`frontend/src/api/analyze.ts` defines the response types shared by the workflow:

- `analysis_id`
- `filename`
- optional device metadata
- control result summaries
- evidence records
- optional unknown-pattern summaries

The client does not manually set the multipart `Content-Type` header. The
browser supplies the boundary when the `FormData` request is sent. The API
base URL defaults to `http://127.0.0.1:8000` and can be changed with
`VITE_API_URL`.

## Evidence presentation

Evidence remains subordinate to the deterministic control result. The detail
dialog displays the control ID/name, result, property, expected and actual
values, source filename, line range, raw configuration excerpt, and explanation.
Missing source information is displayed as `Not available`; the frontend never
creates provenance values.

## Verification

From the repository root:

```bash
PYTHONPATH=backend .venv/bin/python -m pytest backend/tests -q
cd frontend
npm run build
```

Manual smoke tests use the prepared fixtures:

```bash
# Start backend from the repository root
PYTHONPATH=backend .venv/bin/python -m uvicorn app.main:app --app-dir backend --port 8000

# Start frontend in a second terminal
cd frontend
npm run dev -- --host 0.0.0.0
```

Open the Vite URL and select a prepared fixture from `configs/cisco/`,
`configs/fortigate/`, `configs/paloalto/`, or `configs/astranet/`. Verify the
vendor, corresponding results, evidence details, and the AstraNet unknown
pattern card.

For a supported FAIL finding, the page loads a deterministic remediation
recommendation. The reviewer must explicitly choose **Simulate Remediation**.
The UI labels the result as **SIMULATION ONLY**, shows before/after property
values, and identifies the fresh evidence as simulated remediation evidence.
