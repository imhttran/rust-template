# go-template

Full-stack auth template: **Next.js → Go API → PostgreSQL**. The browser only
ever talks to Next.js; the Go API is proxied server-side and never exposed
directly.

```
Browser
   ↓
Next.js        frontend/  → :3000   React UI, routing, SSR/static gen, server components
   ↓
Go API         backend/   → :8080   chi + pgx + JWT + scrypt + email worker
   ↓
PostgreSQL     migrations apply on boot
```

## Quick Start

```bash
./manage.sh       # → [7] First-Time Setup, then → [1] Start All
```

Needs Go 1.22+, Node 20+, and a running PostgreSQL (option 1 refuses to start
if it's down). Dev admin: **admin@mail.com** / **Password1234!** — first login
from a new browser asks for a 2FA code; in development it's always `1234`, and
the browser is trusted afterwards.

Useful menu options beyond setup/start: [5] status, [6] tests, [9] reset DB,
[10] tail logs, [11] re-seed (drop DB + restart backend).

## Docs

- **[docs/FEATURE.md](docs/FEATURE.md)** — what this build does
- **[docs/DATABASE.md](docs/DATABASE.md)** — install Postgres, schema, reset, tests
- **`.env.example`** — every config variable

## Tests

`./manage.sh` → 6 runs backend tests + frontend build. Backend integration
tests need `TEST_DATABASE_URL` (see docs/DATABASE.md).

## Roles

`client` < `staff` < `admin`. Grant via CLI only (no self-service promotion):

```bash
cd backend && go run ./cmd/set-role you@email.com admin
# or: ./manage.sh → [8]
```

## API

19 endpoints under `/api/*` — see `backend/app.go` (`routes()`):

- **Public auth** (8): signup, verify, resend-verification, forgot-password,
  reset-password, login, login/verify (2FA code), login/resend (2FA code)
- **Self-service, any signed-in user** (4): me, profile (get/save),
  change-password
- **Staff/admin** (7): list users, create user, delete, verify/unverify,
  change role, resend verification, reset password
