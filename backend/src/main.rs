// Binary entry point. All logic lives in the library so tests can drive the
// real router — see docs/RUST_MIGRATION.md.

use backend::config::Config;
use backend::queue;
use backend::routes::new_router;
use backend::state::AppState;

#[tokio::main]
async fn main() {
    // set-role subcommand: roles are granted out-of-band, no HTTP endpoint.
    // Deliberately does NOT load .env files — it reads DATABASE_URL directly,
    // like the Go CLI did.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("set-role") {
        if let Err(err) = run_set_role(&args[1..]).await {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }

    backend::config::load_env_files();
    let cfg = Config::load();

    let db = sqlx::PgPool::connect(&cfg.database_url)
        .await
        .unwrap_or_else(|err| backend::fatal("Failed to connect to database", err));

    backend::migrate(&db).await;
    backend::seed_dev_admin(&cfg, &db).await;

    let port = cfg.port;
    let state = AppState {
        cfg: std::sync::Arc::new(cfg),
        db,
    };

    // Email worker: polls the queue and sends (or logs) every 3s.
    tokio::spawn(queue::start_email_worker(state.clone()));

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap_or_else(|err| backend::fatal("failed to bind", err));

    println!("Backend server running at http://localhost:{port}");
    if let Err(err) = axum::serve(listener, new_router(state)).await {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

// Usage: set-role <email> <client|staff|admin>. Exits 1 with a message on any
// failure, mirroring the Go CLI's error handling.
async fn run_set_role(args: &[String]) -> Result<(), String> {
    let usage = || {
        format!(
            "Usage: set-role <email> <{}>",
            backend::roles::ROLES.join("|")
        )
    };
    if args.len() != 2 {
        return Err(usage());
    }
    let (email, role) = (&args[0], &args[1]);
    let dsn = match std::env::var("DATABASE_URL") {
        Ok(dsn) if !dsn.is_empty() => dsn,
        _ => backend::config::DEFAULT_DATABASE_URL.to_string(),
    };
    let db = sqlx::PgPool::connect(&dsn)
        .await
        .map_err(|err| format!("Failed to set role: {err}"))?;
    match backend::set_role(&db, email, role).await {
        Ok(()) => {
            println!("{email} is now {role}");
            Ok(())
        }
        Err(backend::SetRoleError::NoSuchUser(email)) => {
            Err(format!("No user found with email {email}"))
        }
        Err(backend::SetRoleError::InvalidRole) => Err(usage()),
        Err(backend::SetRoleError::Db(err)) => Err(format!("Failed to set role: {err}")),
    }
}
