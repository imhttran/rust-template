# Rust Migration (Go backend → Rust backend)

Goal: replace the Go backend with a Rust backend. **Next.js and PostgreSQL are
unchanged**, and the API contract (routes, status codes, JSON shapes) is
frozen — `frontend/next.config.ts`'s proxy and `backend/app_test.go` define it.

```
Browser → Next.js (:3000) → Rust API (:8080, axum + sqlx + JWT + scrypt) → PostgreSQL
```

## Decisions

- **Database renamed** from `go_template` to `rust_template` (tests use
  `rust_template_test`); all defaults, docs, and `.env.example` updated
  together so both backends stay in agreement during the side-by-side period.
- **axum** (tokio) — community default, router style close to chi.
- **sqlx** — raw SQL like pgx, built-in `PgPool`; no ORM.
- **Single crate** in `backend-rs/`, modules mirroring the Go files; `set-role`
  becomes a subcommand of the same binary.
- **Side-by-side until green**: build `backend-rs/` while Go keeps running,
  then swap `manage.sh`, delete `backend/`, rename. Repo is git-tracked, so
  cutover is reviewable.
- Deliberately skipped: ORM, `tower-http` beyond need, `anyhow`/`thiserror`
  (one small `AppError` enum mirrors Go's `respond`/`fail` helpers).

## Crate map

| Go today           | Rust                                |
| ------------------ | ----------------------------------- |
| chi                | axum                                |
| pgx / pgxpool      | sqlx (`PgPool`)                     |
| encoding/json      | serde + serde_json                  |
| golang-jwt         | jsonwebtoken (HS256, same claims)   |
| x/crypto/scrypt    | scrypt + subtle + hex (same format) |
| net/smtp           | lettre (implicit TLS + STARTTLS)    |
| crypto/rand        | rand                                |
| custom .env loader | hand-rolled port in `config.rs`     |
| `cmd/set-role`     | subcommand (`match env::args()`)    |

## Phases

- [x] **Phase 0 — scaffolding**: crate created, `migrations/` copied (Go keeps
      its copy until cutover), deps pinned.
- [x] **Phase 1 — plumbing**: config + env loader, `PgPool`, embedded
      migrations via `raw_sql`, axum boot + `/api/healthz` stub.
      _Exit: `cargo build` clean; boot applies both migrations
      (`schema_migrations` = 1, 2)._
- [x] **Phase 2 — auth**: scrypt hash/verify (exact `salt:hash` hex, proven
      against a Go-created hash by a pinned unit test), JWT, `requireAuth`/
      `requireRole`/`parseID`, onboarding gates, response helpers, and the
      whole of `auth.go` (signup, verify, resend-verification, forgot/reset
      password, login, 2FA verify/resend, me, change-password) — ported as one
      cohesive file since `loginAs` drives the full 2FA flow.
      _Exit: 4 ported integration tests + 4 unit tests pass._
- [x] **Phase 3 — profile**: profile get/save, the one-time registration
      validation (required fields, communication preference, phone/zip/URL,
      US state + country lists), camelCase row serialization, unique-
      violation → "Profile already exists". _Exit: profile_flow test passes
      (gate lift, save, duplicate, validation 400s, GET with US default)._
- [x] **Phase 4 — admin**: all 7 staff/admin routes (list with role-scoped
      visibility, create, delete with self-delete block, verification patch
      with loose boolean decode, role patch with invalid-value + self-change
      blocks, staff resend, admin id-keyed password reset), `parseID` guard,
      23505 mapping. _Exit: users_rbac, delete_own_account,
      patch_role_invalid_value tests pass._
- [x] **Phase 5 — email queue + mailer**: `process_email_queue` (bounded
      retries, `ponytail` no-backoff comment preserved), 3s polling worker via
      `tokio::time::interval`, lettre transport (implicit TLS on :465,
      opportunistic STARTTLS otherwise, plain auth, CRLF header guard, log
      transport when `SMTP_HOST` unset). _Exit: worker test drains the queue
      to 'sent'; runtime smoke test logs the email and flips the row._
- [x] **Phase 6 — CLI + seed**: `set-role` subcommand on the main binary
      (`backend set-role <email> <role>` — no `.env` loading, reads
      `DATABASE_URL` directly, exits 1 on failure, like the Go CLI); role
      logic lives in the lib (`set_role` + `SetRoleError`) and is tested
      directly; dev-admin seed at boot (development only, idempotent,
      pre-fills the profile). _Exit: seed + set-role tests pass; CLI verified
      end-to-end (promote, restore, unknown user, usage)._
- [x] **Phase 7 — cutover**: `manage.sh` → `cargo run`/`cargo test`/`cargo run
    -- set-role`, pre-commit hook → cargo, README/DATABASE.md/FEATURE.md/
      `.env.example`/frontend comments updated, root `.gitignore` cleaned,
      Go `backend/` deleted (recoverable from git history), `backend-rs/` →
      `backend/`. _Exit: full test suite green from the new path; backend
      boots, seeds, serves :8080; set-role works via the manage.sh path._

## Done

The conversion is complete: the Rust backend is a drop-in replacement at the
same path (`backend/`), same port (:8080), same database (`rust_template`),
same 19-endpoint API contract, verified against the ported test suite.
During the migration both backends ran side-by-side; the Go implementation
lives in git history.

## Parity gotchas (the hard parts)

1. **Password hash format** — Node-compatible `hex(salt):hex(key)`, N=16384
   (`log_n = 14` in the Rust crate), r=8, p=1, 16-byte salt, 64-byte key.
   Existing DB hashes must verify unchanged.
2. **JWT** — HS256 only, `{email, exp, iat}`, 1h expiry; signed token with a
   missing/empty email claim must fail as "Invalid or expired token".
3. **Response shapes** — tests assert exact bodies: `msg()` (message only) vs
   `fail()` (success + message) vs `respond500()` variants. Port semantics, not
   just status codes.
4. **decodeJSON leniency** — missing/unparsable body decodes as an empty
   struct; route-level validation produces the 400s. Don't use axum's `Json`
   extractor for those bodies (it rejects bad JSON); read the body and
   `serde_json::from_str(...).unwrap_or_default()`.
5. **Unique violation** — check DB error code `"23505"` (Go checked
   `pgconn.PgError.Code`).
6. **Migrations** — `sqlx::raw_sql` uses the simple query protocol and runs
   the multi-statement files directly; Go's `splitStatements` comment-stripping
   hack is not needed.
7. **Path params** — axum 0.8 uses `/{id}`, not chi's `:id`.

## Env loading (unchanged contract)

Root `.env` always wins (existing env vars never overwritten); `.env.dev`
fills in only when `NODE_ENV` is unset or `development`; files resolved from
cwd then the parent dir. Ported verbatim into `config.rs`.
