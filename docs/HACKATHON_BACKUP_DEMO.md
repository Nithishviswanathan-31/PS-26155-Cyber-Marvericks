# API Backup Demo

Use this only if the browser UI is unavailable. Start the backend, then use
the actual endpoints below. Replace placeholders with IDs returned by the
previous response.

```bash
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/api/demo/reset

curl -X POST \
  -F "file=@configs/cisco/noncompliant.conf" \
  http://127.0.0.1:8000/api/analyze

curl http://127.0.0.1:8000/api/remediation/{analysis_id}
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"remediation_id":"{remediation_id}"}' \
  http://127.0.0.1:8000/api/remediation/{analysis_id}/simulate

curl -OJ http://127.0.0.1:8000/api/reports/{analysis_id}/pdf
```

For adaptive learning:

```bash
curl -X POST -F "file=@configs/astranet/unknown-pattern.conf" http://127.0.0.1:8000/api/analyze
curl -X POST http://127.0.0.1:8000/api/mappings/{pattern_id}/suggest
curl -X POST -H "Content-Type: application/json" \
  -d '{"reviewer_id":"demo-reviewer","semantic_mapping":{"management.ssh_enabled":true,"management.telnet_enabled":false}}' \
  http://127.0.0.1:8000/api/mappings/{pattern_id}/approve
curl -X POST http://127.0.0.1:8000/api/analyze/{analysis_id}/reanalyze
curl -OJ http://127.0.0.1:8000/api/reports/{reanalyzed_analysis_id}/pdf
```

If suggestion or re-analysis fails, do not fake a result. Explain the failure
and continue with the independent deterministic Cisco path. If PDF generation
fails, continue with the already-generated JSON results and evidence.
