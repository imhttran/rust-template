// Runtime configuration, ported from app.go's Config/loadConfig, plus the
// .env loader from main.go: a personal root .env always wins (existing env
// vars are never overwritten); the committed dev profile only fills in when
// NODE_ENV is unset or development.

use std::env;
use std::path::Path;

// Default DSN for local development, used when DATABASE_URL is unset (both by
// the server and the set-role subcommand).
pub const DEFAULT_DATABASE_URL: &str =
    "postgres://postgres:postgres@localhost:5432/rust_template?sslmode=disable";

pub struct Config {
    pub port: u16,
    pub database_url: String,
    pub env: String, // development | qa | production
    pub frontend_url: String,

    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_pass: String,
    pub mail_from: String,

    pub max_attempts: i32,
    pub email_verification_required: bool,
    pub jwt_secret: String,
}

impl Config {
    pub fn load() -> Config {
        let env = env_or("NODE_ENV", "development");
        let jwt_secret = match env::var("JWT_SECRET") {
            Ok(s) if !s.is_empty() => s,
            _ => {
                if env == "production" {
                    eprintln!("JWT_SECRET must be set in production");
                    std::process::exit(1);
                }
                eprintln!("[config] JWT_SECRET not set — using insecure dev fallback");
                "dev-insecure-jwt-secret".to_string()
            }
        };
        Config {
            port: int_or("PORT", 8080) as u16,
            database_url: env_or("DATABASE_URL", DEFAULT_DATABASE_URL),
            env,
            frontend_url: env_or("FRONTEND_URL", "http://localhost:3000"),
            smtp_host: env::var("SMTP_HOST").unwrap_or_default(),
            smtp_port: int_or("SMTP_PORT", 587) as u16,
            smtp_user: env::var("SMTP_USER").unwrap_or_default(),
            smtp_pass: env::var("SMTP_PASS").unwrap_or_default(),
            mail_from: env_or("MAIL_FROM", "no-reply@example.com"),
            max_attempts: int_or("MAX_ATTEMPTS", 3),
            // Bypass email verification when EMAIL_VERIFICATION_REQUIRED=false.
            email_verification_required: !matches!(
                env::var("EMAIL_VERIFICATION_REQUIRED"),
                Ok(v) if v == "false"
            ),
            jwt_secret,
        }
    }
}

// Go's envOr: an empty value counts as unset.
fn env_or(key: &str, fallback: &str) -> String {
    match env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => fallback.to_string(),
    }
}

// Go's intOr: unparsable or non-positive → fallback.
fn int_or(key: &str, fallback: i32) -> i32 {
    match env::var(key).ok().and_then(|v| v.parse::<i32>().ok()) {
        Some(n) if n > 0 => n,
        _ => fallback,
    }
}

pub fn load_env_files() {
    fn apply_env(path: &Path) {
        let Ok(contents) = std::fs::read_to_string(path) else {
            return;
        };
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let mut value = value.trim().to_string();
            if value.len() >= 2
                && ((value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\'')))
            {
                value = value[1..value.len() - 1].to_string();
            }
            if env::var_os(key).is_none() {
                env::set_var(key, value);
            }
        }
    }
    for dir in [".", ".."] {
        let path = Path::new(dir).join(".env");
        if path.exists() {
            apply_env(&path);
            break;
        }
    }
    // Unset counts as development — otherwise .env.dev could never be seen,
    // since it is itself what sets NODE_ENV.
    let node_env = env::var("NODE_ENV").unwrap_or_default();
    if node_env.is_empty() || node_env == "development" {
        for dir in [".", ".."] {
            let path = Path::new(dir).join(".env.dev");
            if path.exists() {
                apply_env(&path);
                break;
            }
        }
    }
}
