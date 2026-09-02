// Rust port of the Go backend — see docs/RUST_MIGRATION.md.
// Library crate so the integration tests (tests/) exercise the real router.

pub mod auth;
pub mod config;
pub mod mail;
pub mod profile;
pub mod queue;
pub mod roles;
pub mod routes;
pub mod state;
pub mod users;
pub mod validators;

use sqlx::PgPool;

// Ordered migrations; each runs once, recorded by version in schema_migrations.
pub const MIGRATIONS: &[(i32, &str, &str)] = &[
    (
        1,
        "001_init.sql",
        include_str!("../migrations/001_init.sql"),
    ),
    (2, "002_2fa.sql", include_str!("../migrations/002_2fa.sql")),
];

// Applied at boot and recorded in schema_migrations. raw_sql uses the simple
// query protocol, so the multi-statement files run directly — no comment
// stripping needed (that was a pgx extended-protocol workaround).
pub async fn migrate(db: &PgPool) {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version    INTEGER PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )",
    )
    .execute(db)
    .await
    .unwrap_or_else(|err| fatal("migrate", err));

    for (version, name, sql) in MIGRATIONS {
        let applied: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)",
        )
        .bind(version)
        .fetch_one(db)
        .await
        .unwrap_or_else(|err| fatal("migrate", err));
        if applied {
            continue;
        }
        sqlx::raw_sql(sql)
            .execute(db)
            .await
            .unwrap_or_else(|err| fatal("migrate", err));
        sqlx::query("INSERT INTO schema_migrations (version) VALUES ($1)")
            .bind(version)
            .execute(db)
            .await
            .unwrap_or_else(|err| fatal("migrate", err));
        println!("[migrate] applied {name}");
    }
}

pub fn fatal(context: &str, err: impl std::fmt::Display) -> ! {
    eprintln!("{context}: {err}");
    std::process::exit(1);
}

// ---- out-of-band role management (the set-role subcommand) ----

// Debug: the integration test's .expect needs it.
#[derive(Debug)]
pub enum SetRoleError {
    InvalidRole,
    NoSuchUser(String),
    Db(sqlx::Error),
}

// Sets an existing user's role. There's no HTTP endpoint for this on purpose —
// admin/staff are granted out-of-band (usage: set-role <email> <role>).
pub async fn set_role(db: &PgPool, email: &str, role: &str) -> Result<(), SetRoleError> {
    if roles::role_index(role).is_none() {
        return Err(SetRoleError::InvalidRole);
    }
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)")
        .bind(email)
        .fetch_one(db)
        .await
        .map_err(SetRoleError::Db)?;
    if !exists {
        return Err(SetRoleError::NoSuchUser(email.to_string()));
    }
    sqlx::query("UPDATE users SET role = $1 WHERE email = $2")
        .bind(role)
        .bind(email)
        .execute(db)
        .await
        .map_err(SetRoleError::Db)?;
    Ok(())
}

// Dev-only convenience: guarantees a known admin login exists locally, so
// there's no manual set-role step for local dev. Gated on NODE_ENV so these
// credentials can never appear in a qa/prod database.
pub async fn seed_dev_admin(cfg: &config::Config, db: &PgPool) {
    if cfg.env != "development" {
        return;
    }
    const DEV_ADMIN_EMAIL: &str = "admin@mail.com";
    const DEV_ADMIN_PASSWORD: &str = "Password1234!";
    let hashed = auth::hash_password(DEV_ADMIN_PASSWORD);
    // Conflict (no row) and DB errors both fall through to the lookup, like
    // Go's err != nil branch.
    let inserted: Option<i32> = sqlx::query_scalar(
        "INSERT INTO users (email, password, role, email_verified)
         VALUES ($1, $2, 'admin', true)
         ON CONFLICT (email) DO NOTHING
         RETURNING id",
    )
    .bind(DEV_ADMIN_EMAIL)
    .bind(hashed)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    let id = match inserted {
        Some(id) => id,
        // Already exists (or the insert failed for another reason) — look it up.
        None => {
            let existing =
                sqlx::query_scalar::<sqlx::Postgres, i32>("SELECT id FROM users WHERE email = $1")
                    .bind(DEV_ADMIN_EMAIL)
                    .fetch_one(db)
                    .await;
            match existing {
                Ok(id) => id,
                Err(err) => {
                    eprintln!("[seed] failed: {err}");
                    return;
                }
            }
        }
    };
    // Pre-fill the profile too, so the dev admin isn't stopped by its own
    // onboarding gate (see the onboarding gates in routes.rs).
    if let Err(err) = sqlx::query(
        "INSERT INTO user_profiles (user_id, first_name, last_name, address, state, zip, phone)
         VALUES ($1, 'Dev', 'Admin', 'N/A', 'N/A', '00000', 'N/A')
         ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(id)
    .execute(db)
    .await
    {
        eprintln!("[seed] failed: {err}");
        return;
    }
    eprintln!("[seed] dev admin ready: {DEV_ADMIN_EMAIL}");
}
