# V2 local authentication and roles

Authentication extends the existing SQLite demo; it does not migrate or rewrite
analysis, inventory, mapping, proposal, knowledge or evidence records.

## Modes and setup

`AUTH_REQUIRED=false` (the existing development default) preserves unauthenticated
offline audit workflows and their legacy reviewer fields. The UI labels this mode
as **authentication disabled**. It is not a secured deployment. User administration
always requires a real signed-in ADMIN, including in offline mode. An explicitly
supplied invalid bearer token never falls back to the offline principal.

For a secured local demo, configure the process environment before starting:

- `AUTH_REQUIRED=true`
- `AUTH_SECRET`: a random secret with at least 32 bytes; e.g. generate with
  `python -c "import secrets; print(secrets.token_urlsafe(48))"` and place the result
  in your local process environment, not source control.
- `AUTH_TTL_SECONDS`: 60 through 86400 (default 3600).
- `DEMO_ADMIN_PASSWORD`, `DEMO_AUDITOR_PASSWORD`, `DEMO_REVIEWER_PASSWORD`:
  local passwords of 12–256 characters supplied by the operator.
- Optional `DEMO_ADMIN_USERNAME`, `DEMO_AUDITOR_USERNAME`,
  `DEMO_REVIEWER_USERNAME` (defaults: admin, auditor, reviewer).

From the repository root in PowerShell, set `$env:PYTHONPATH='backend'`, then run
`python -m app.seed_users`. Seeding is explicit, local-only and idempotent: it creates
missing configured users without replacing existing passwords or roles. Then start
`python -m uvicorn app.main:app --host 127.0.0.1 --port 8000` and the existing Vite
frontend. Both work without external services. Environment files are not loaded
automatically. Never put actual credentials in tracked files or shell transcripts.
Clear seed-password environment variables after seeding.

`APP_ENV=production` refuses startup if auth is disabled, and blocks demo seeding.
Demo reset remains admin-only in secured mode and never creates users, deletes
users/sessions, or erases authentication audit events. No default passwords or
signing secrets ship with the project.

## Permission matrix

| Capability | ADMIN | AUDITOR | REVIEWER |
| --- | --- | --- | --- |
| Read all audit data, evidence, histories and PDFs | Yes | Yes | Yes |
| Single upload, batch submission, remediation simulation | Yes | Yes | No |
| Generate interpretation/mapping proposals | Yes | No | Yes |
| Approve/correct/reject mapping and linked proposal | Yes | No | Yes |
| Deactivate knowledge | Yes | No | Yes |
| Explicit re-analysis using already-approved mappings | Yes | Yes | Yes |
| Manage users, local demo reset | Yes | No | No |

All audit routers share the authentication dependency. Mutation permissions are
enumerated by route name and default to deny for new unclassified mutations.
Read access is intentionally a shared audit workspace: these roles are not tenant
or per-device ownership boundaries. `/health` and login remain public; API docs
contain schemas only. Invalid/missing authentication returns structured 401;
insufficient role returns structured 403. CORS is not used as authorization.

## Identity and durable audit

The server takes `user_id` and current role from the persisted authenticated user,
not bearer role claims or request-body reviewer fields. Legacy `reviewer_id` remains
a required compatibility field for the existing mapping contracts, but its value
is ignored for authenticated actions. Mapping approvals, proposal review events,
and knowledge deactivation record the authenticated user ID in their existing
reviewer column. Historical identities remain readable without a user foreign key.

`auth_events` stores server-derived actor ID, role, action, target and timestamp.
User changes and their audit events commit together. Audit workflow mutations have
REQUESTED and COMPLETED/FAILED entries; payloads, passwords, tokens and uploaded
configuration text are never logged. Generic workflow audit entries are separate
transactions from existing business writes: a process crash can leave a REQUESTED
entry without a terminal event. Mapping/proposal business audit history still applies.

## Session and password security

Password hashes are salted PBKDF2-HMAC-SHA256 (600,000 iterations), with a versioned
format; verification also reads the initial primitive's 310,000-iteration format.
Public user responses omit hashes. Credential and validation errors do not echo
passwords. Login failures have a uniform message and dummy-password hashing for
unknown users, with a persisted ten-attempt/five-minute username throttle.

Bearer tokens retain the existing HMAC-SHA256 format, adding random session IDs.
SQLite stores only the token SHA-256 digest, user ID, expiry and revocation state.
Every request verifies the signature, expiry, session state and current enabled
user. Logout revokes the token. Role/password/enabled-state changes revoke all
sessions for that user. Changing the signing secret invalidates existing tokens.
No refresh tokens are issued; expiry requires login again.

The frontend uses one authenticated fetch wrapper, tab-scoped sessionStorage,
protected workspace mounting, 401 session clearing, 403 feedback, and role-aware
controls. SessionStorage is accessible to JavaScript, so XSS remains a token-theft
risk. Treat bearer tokens as secrets; use HTTPS for any non-loopback access. Tokens
are reusable until logout/expiry/revocation, as expected for bearer sessions.

User administration supports list/create and PATCH role, active, password. A
transaction serializes final-enabled-admin protection; no delete-user endpoint
exists. This is a local/offline single-workspace implementation, without MFA,
password recovery email, enterprise identity integration or multi-tenant RBAC.

## Validation

Run from the repository root with `PYTHONPATH=backend`:
`python -m pytest backend/tests -q -p no:cacheprovider`.
The authentication module uses isolated SQLite security databases, real passwords,
signed tokens and actual dependencies. Existing tests continue in offline mode.
On Windows, use a fresh pytest `--basetemp` directory if the default temp ACLs fail.
Frontend checks: `npm run build` in `frontend` (includes TypeScript), plus
`node --test tests/auth-http.test.mjs` for the shared session/HTTP layer.
