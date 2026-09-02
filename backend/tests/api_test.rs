// Port of app_test.go — integration tests driving the real router via
// tower's oneshot (no sockets). They run against a real Postgres; without
// TEST_DATABASE_URL they exit early, so `cargo test` passes with no
// database. Set e.g.:
//
//	TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/rust_template_test?sslmode=disable \
//	  cargo test --test api_test
//
// Every test creates its own uniquely-addressed fixtures (unique email per
// run), so reruns against a dirty database still pass.

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use backend::config::Config;
use backend::routes::new_router;
use backend::state::AppState;
use http_body_util::BodyExt;
use regex::Regex;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tower::ServiceExt;

static TEST_RUN: AtomicU64 = AtomicU64::new(0);

// Each test connects its own short-lived pool (tests run in parallel, each on
// its own current-thread runtime — sharing one pool across dying runtimes
// hangs pool acquisition). Migrations are idempotent, so every test runs them.
fn test_dsn() -> Option<String> {
    match std::env::var("TEST_DATABASE_URL") {
        Ok(dsn) if !dsn.is_empty() => Some(dsn),
        _ => {
            eprintln!("TEST_DATABASE_URL not set; skipping database-backed tests");
            None
        }
    }
}

// Dev-like config. env is deliberately empty (not "development") so login
// codes are random — login_as pulls them from the queued email. The seed test
// passes "development" to exercise the dev-admin path.
fn test_config(env: &str) -> Config {
    Config {
        port: 0,
        database_url: String::new(),
        env: env.to_string(),
        frontend_url: "http://localhost:3000".to_string(),
        smtp_host: String::new(),
        smtp_port: 587,
        smtp_user: String::new(),
        smtp_pass: String::new(),
        mail_from: "no-reply@example.com".to_string(),
        max_attempts: 3,
        email_verification_required: false, // same bypass the Node tests use
        jwt_secret: "test-secret".to_string(),
    }
}

fn test_state(pool: PgPool) -> AppState {
    AppState {
        cfg: Arc::new(test_config("")),
        db: pool,
    }
}

struct TestEnv {
    router: Router,
    pool: PgPool,
    email: String,
    password: String,
}

async fn new_test_env() -> Option<TestEnv> {
    let dsn = test_dsn()?;
    let pool = PgPool::connect(&dsn)
        .await
        .expect("connect TEST_DATABASE_URL");
    backend::migrate(&pool).await; // same migrations main() runs
    let router = new_router(test_state(pool.clone()));
    let run = TEST_RUN.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    Some(TestEnv {
        router,
        pool,
        email: format!("rusttest-{run}-{nano}@mail.com", nano = nanos % 100_000),
        password: "Valid123!".to_string(),
    })
}

impl TestEnv {
    // Explicit (not Drop): drop-time spawns race the test runtime teardown.
    // Deletes cascade to the profile, then the queued email rows. The pool is
    // closed last so the test's runtime doesn't outlive its connections.
    async fn cleanup(self) {
        let _ = sqlx::query("DELETE FROM users WHERE email = $1")
            .bind(&self.email)
            .execute(&self.pool)
            .await;
        let _ = sqlx::query(r#"DELETE FROM email_queue WHERE "to" = $1"#)
            .bind(&self.email)
            .execute(&self.pool)
            .await;
        self.pool.close().await;
    }
}

async fn do_json(
    router: &Router,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let (status, _, body) = do_json_with_headers(router, method, path, token, body).await;
    (status, body)
}

// Like do_json, but also returns the response headers (session-renewal test).
async fn do_json_with_headers(
    router: &Router,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, HeaderMap, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if !token.is_empty() {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let raw = body.map(|v| v.to_string()).unwrap_or_default();
    let response = router
        .clone()
        .oneshot(builder.body(Body::from(raw)).expect("valid request"))
        .await
        .expect("router is infallible");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn login_as(env: &TestEnv, email: &str, password: &str) -> String {
    let (status, body) = do_json(
        &env.router,
        "POST",
        "/api/login",
        "",
        Some(json!({ "email": email, "password": password })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login for {email} failed ({body})");
    let mut token = body["token"].as_str().unwrap_or_default().to_string();
    assert!(!token.is_empty(), "login for {email} returned no token");
    if body["twoFactorRequired"].as_bool().unwrap_or(false) {
        let code = fetch_login_code(&env.pool, email).await;
        let (status, body) = do_json(
            &env.router,
            "POST",
            "/api/login/verify",
            "",
            Some(json!({
                "token": &token,
                "code": code,
                "deviceId": "test-device",
            })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "2FA verify for {email} failed ({body})"
        );
        token = body["token"].as_str().unwrap_or_default().to_string();
        assert!(
            !token.is_empty(),
            "2FA verify for {email} returned no token"
        );
    }
    token
}

// Pulls the newest queued email for the address and extracts the 4-digit
// login code from its body (the worker isn't running in tests).
async fn fetch_login_code(pool: &PgPool, email: &str) -> String {
    let body_text: String = sqlx::query_scalar(
        r#"SELECT body FROM email_queue WHERE "to" = $1 ORDER BY id DESC LIMIT 1"#,
    )
    .bind(email)
    .fetch_one(pool)
    .await
    .expect("fetch login code email");
    Regex::new(r"\b\d{4}\b")
        .unwrap()
        .find(&body_text)
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| panic!("no 4-digit code in queued email: {body_text:?}"))
}

// Fills in the profile so onboarding gates don't mask the behavior under test.
async fn fill_profile(env: &TestEnv, token: &str) {
    let (status, body) = do_json(
        &env.router,
        "POST",
        "/api/profile",
        token,
        Some(json!({
            "firstName": "Test", "lastName": "User", "address": "1 Test St",
            "state": "CA", "zip": "94043", "phone": "555-123-4567",
            "communicationPreference": "email",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "profile setup failed: {body}");
}

// Sets a user's role directly in the store, like the Node tests do.
async fn set_role(env: &TestEnv, email: &str, role: &str) {
    sqlx::query("UPDATE users SET role = $1 WHERE email = $2")
        .bind(role)
        .bind(email)
        .execute(&env.pool)
        .await
        .expect("set role");
}

async fn own_user_id(env: &TestEnv, token: &str) -> i32 {
    let (status, body) = do_json(&env.router, "GET", "/api/me", token, None).await;
    assert_eq!(status, StatusCode::OK, "/api/me failed: {body}");
    body["user"]["id"].as_i64().expect("user id") as i32
}

// ---- tests ----

#[tokio::test]
async fn signup_weak_password() {
    let Some(env) = new_test_env().await else {
        return;
    };
    let (status, body) = do_json(
        &env.router,
        "POST",
        "/api/signup",
        "",
        Some(json!({ "email": &env.email, "password": "S1!" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body {body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("at least 8 characters"),
        "message = {body}, want it to mention at least 8 characters"
    );
    env.cleanup().await;
}

#[tokio::test]
async fn signup_and_login_happy_path() {
    let Some(env) = new_test_env().await else {
        return;
    };
    let (status, body) = do_json(
        &env.router,
        "POST",
        "/api/signup",
        "",
        Some(json!({ "email": &env.email, "password": &env.password })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body {body}");
    assert_eq!(body["success"], json!(true), "body {body}");

    let (status, body) = do_json(
        &env.router,
        "POST",
        "/api/login",
        "",
        Some(json!({ "email": &env.email, "password": &env.password })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body {body}");
    assert!(
        !body["token"].as_str().unwrap_or_default().is_empty(),
        "login returned no token: {body}"
    );
    env.cleanup().await;
}

#[tokio::test]
async fn me_requires_token() {
    let Some(env) = new_test_env().await else {
        return;
    };

    let (status, _) = do_json(&env.router, "GET", "/api/me", "", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no token");

    do_json(
        &env.router,
        "POST",
        "/api/signup",
        "",
        Some(json!({ "email": &env.email, "password": &env.password })),
    )
    .await;
    let token = login_as(&env, &env.email, &env.password).await;

    let (status, body) = do_json(&env.router, "GET", "/api/me", &token, None).await;
    assert_eq!(status, StatusCode::OK, "with token: body {body}");
    assert_eq!(
        body["user"]["email"],
        json!(&env.email),
        "me.user.email = {body}"
    );
    env.cleanup().await;
}

// The gate lift + validation + unique-violation path, end to end.
#[tokio::test]
async fn profile_flow() {
    let Some(env) = new_test_env().await else {
        return;
    };
    do_json(
        &env.router,
        "POST",
        "/api/signup",
        "",
        Some(json!({ "email": &env.email, "password": &env.password })),
    )
    .await;
    let token = login_as(&env, &env.email, &env.password).await;

    // Before saving, the profile is a 200 with null (the absence is the gate).
    let (status, body) = do_json(&env.router, "GET", "/api/profile", &token, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["profile"].is_null(), "{body}");

    fill_profile(&env, &token).await;

    // Second save hits the unique constraint → "Profile already exists".
    let (status, body) = do_json(
        &env.router,
        "POST",
        "/api/profile",
        &token,
        Some(json!({
            "firstName": "Test", "lastName": "User", "address": "1 Test St",
            "state": "CA", "zip": "94043", "phone": "555-123-4567",
            "communicationPreference": "email",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["message"], json!("Profile already exists"), "{body}");

    // The saved row comes back with camelCase fields and the US default.
    let (status, body) = do_json(&env.router, "GET", "/api/profile", &token, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["profile"]["firstName"], json!("Test"), "{body}");
    assert_eq!(
        body["profile"]["communicationPreference"],
        json!("email"),
        "{body}"
    );
    assert_eq!(body["profile"]["country"], json!("US"), "{body}");
    assert!(body["profile"]["address2"].is_null(), "{body}");

    // Validation runs before the insert, so these 400s don't mention profiles.
    let cases: [(Value, &str); 3] = [
        (
            json!({
                "firstName": "Test", "lastName": "User", "address": "1 Test St",
                "state": "CA", "zip": "94043", "phone": "not-a-phone",
                "communicationPreference": "email",
            }),
            "Phone number is invalid",
        ),
        (
            json!({
                "firstName": "Test", "lastName": "User", "address": "1 Test St",
                "state": "XX", "zip": "94043", "phone": "555-123-4567",
                "communicationPreference": "email",
            }),
            "State is invalid",
        ),
        (
            json!({
                "firstName": "Test", "lastName": "User", "address": "1 Test St",
                "state": "CA", "phone": "555-123-4567",
                "communicationPreference": "email",
            }),
            "Missing required field(s): zip",
        ),
    ];
    for (payload, want) in cases {
        let (status, body) =
            do_json(&env.router, "POST", "/api/profile", &token, Some(payload)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["message"], json!(want), "{body}");
    }

    env.cleanup().await;
}

// RBAC ladder on /api/users: client rejected, staff allowed (non-admin rows
// only), admin allowed.
#[tokio::test]
async fn users_rbac() {
    let Some(env) = new_test_env().await else {
        return;
    };
    do_json(
        &env.router,
        "POST",
        "/api/signup",
        "",
        Some(json!({ "email": &env.email, "password": &env.password })),
    )
    .await;
    let token = login_as(&env, &env.email, &env.password).await;
    fill_profile(&env, &token).await; // lift the profile gate so RBAC is what's under test

    // Client is rejected.
    let (status, _) = do_json(&env.router, "GET", "/api/users", &token, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "client");

    // Staff is allowed.
    set_role(&env, &env.email, "staff").await;
    let (status, body) = do_json(&env.router, "GET", "/api/users", &token, None).await;
    assert_eq!(status, StatusCode::OK, "staff: {body}");
    assert!(body["users"].is_array(), "staff: missing users key: {body}");

    // Admin is allowed.
    set_role(&env, &env.email, "admin").await;
    let (status, _) = do_json(&env.router, "GET", "/api/users", &token, None).await;
    assert_eq!(status, StatusCode::OK, "admin");

    env.cleanup().await;
}

// An admin deleting their own account is blocked before the DB is touched.
#[tokio::test]
async fn delete_own_account() {
    let Some(env) = new_test_env().await else {
        return;
    };
    do_json(
        &env.router,
        "POST",
        "/api/signup",
        "",
        Some(json!({ "email": &env.email, "password": &env.password })),
    )
    .await;
    let token = login_as(&env, &env.email, &env.password).await;
    fill_profile(&env, &token).await;
    set_role(&env, &env.email, "admin").await;

    let id = own_user_id(&env, &token).await;
    let (status, body) = do_json(
        &env.router,
        "DELETE",
        &format!("/api/users/{id}"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body {body}");
    assert_eq!(
        body["message"],
        json!("Cannot delete your own account"),
        "{body}"
    );

    env.cleanup().await;
}

#[tokio::test]
async fn patch_role_invalid_value() {
    let Some(env) = new_test_env().await else {
        return;
    };
    do_json(
        &env.router,
        "POST",
        "/api/signup",
        "",
        Some(json!({ "email": &env.email, "password": &env.password })),
    )
    .await;
    let token = login_as(&env, &env.email, &env.password).await;
    fill_profile(&env, &token).await;
    set_role(&env, &env.email, "admin").await;

    let id = own_user_id(&env, &token).await;
    let (status, body) = do_json(
        &env.router,
        "PATCH",
        &format!("/api/users/{id}/role"),
        &token,
        Some(json!({ "role": "wizard" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body {body}");
    assert_eq!(
        body["message"],
        json!("role must be one of: client, staff, admin"),
        "{body}"
    );

    env.cleanup().await;
}

// The queue worker drains pending rows: signup queues welcome + verification,
// login queues the 2FA code; with SMTP_HOST unset the log transport succeeds,
// so everything should flip to 'sent'.
#[tokio::test]
async fn email_queue_worker_marks_sent() {
    let Some(env) = new_test_env().await else {
        return;
    };
    do_json(
        &env.router,
        "POST",
        "/api/signup",
        "",
        Some(json!({ "email": &env.email, "password": &env.password })),
    )
    .await;
    login_as(&env, &env.email, &env.password).await;

    let state = test_state(env.pool.clone());
    // Drain in rounds — parallel tests are enqueueing concurrently, so one
    // LIMIT 10 batch may not cover this user's rows yet.
    let mut processed = 0;
    for _ in 0..10 {
        let n = backend::queue::process_email_queue(&state, 10).await;
        processed += n;
        if n == 0 {
            break;
        }
    }
    assert!(
        processed >= 3,
        "expected at least welcome+verification+login-code, got {processed}"
    );

    let unsent: i64 = sqlx::query_scalar(
        r#"SELECT count(*) FROM email_queue WHERE "to" = $1 AND status <> 'sent'"#,
    )
    .bind(&env.email)
    .fetch_one(&env.pool)
    .await
    .expect("count unsent");
    assert_eq!(unsent, 0, "worker left unsent rows behind");

    env.cleanup().await;
}

// The out-of-band role grant: valid roles update, unknown emails and invalid
// roles are rejected, matching the Go CLI.
#[tokio::test]
async fn set_role_subcommand() {
    let Some(env) = new_test_env().await else {
        return;
    };
    do_json(
        &env.router,
        "POST",
        "/api/signup",
        "",
        Some(json!({ "email": &env.email, "password": &env.password })),
    )
    .await;

    let result = backend::set_role(&env.pool, "nobody@mail.com", "admin").await;
    assert!(matches!(result, Err(backend::SetRoleError::NoSuchUser(_))));

    let result = backend::set_role(&env.pool, &env.email, "wizard").await;
    assert!(matches!(result, Err(backend::SetRoleError::InvalidRole)));

    backend::set_role(&env.pool, &env.email, "staff")
        .await
        .expect("set role");
    let role: String = sqlx::query_scalar("SELECT role FROM users WHERE email = $1")
        .bind(&env.email)
        .fetch_one(&env.pool)
        .await
        .expect("role");
    assert_eq!(role, "staff");

    env.cleanup().await;
}

// Dev-admin seed: creates (and re-creates idempotently) admin@mail.com with a
// pre-filled profile, so local dev needs no manual set-role.
#[tokio::test]
async fn dev_admin_seed() {
    let Some(dsn) = test_dsn() else { return };
    let pool = PgPool::connect(&dsn)
        .await
        .expect("connect TEST_DATABASE_URL");
    backend::migrate(&pool).await;

    let cfg = test_config("development");
    backend::seed_dev_admin(&cfg, &pool).await;
    backend::seed_dev_admin(&cfg, &pool).await; // second run is a no-op

    let role: String = sqlx::query_scalar("SELECT role FROM users WHERE email = 'admin@mail.com'")
        .fetch_one(&pool)
        .await
        .expect("seeded admin exists");
    assert_eq!(role, "admin");
    let profile_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM user_profiles p JOIN users u ON u.id = p.user_id
            WHERE u.email = 'admin@mail.com'
        )",
    )
    .fetch_one(&pool)
    .await
    .expect("profile check");
    assert!(profile_exists, "seeded admin should have a profile");

    let _ = sqlx::query("DELETE FROM users WHERE email = 'admin@mail.com'")
        .execute(&pool)
        .await; // cascades profile
    let _ = sqlx::query(r#"DELETE FROM email_queue WHERE "to" = 'admin@mail.com'"#)
        .execute(&pool)
        .await;
    pool.close().await;
}

// Sliding sessions: a token deep into its life is renewed on successful use
// (X-Renewed-Token), the renewed token is a normal bearer, a full-life token
// is not renewed, and a hard-expired one is rejected.
#[tokio::test]
async fn session_slides_while_active() {
    let Some(env) = new_test_env().await else {
        return;
    };
    do_json(
        &env.router,
        "POST",
        "/api/signup",
        "",
        Some(json!({ "email": &env.email, "password": &env.password })),
    )
    .await;

    // 60 seconds left of the 10-minute window → renewed on use.
    let aging = backend::auth::issue_token_with_ttl(&env.email, "test-secret", 60);
    let (status, headers, _) =
        do_json_with_headers(&env.router, "GET", "/api/me", &aging, None).await;
    assert_eq!(status, StatusCode::OK, "aging token should still work");
    let renewed = headers
        .get("X-Renewed-Token")
        .and_then(|v| v.to_str().ok())
        .expect("aging token should be renewed")
        .to_string();
    assert_ne!(renewed, aging, "renewal must be a new token");

    // The renewed token is a normal bearer.
    let (status, _) = do_json(&env.router, "GET", "/api/me", &renewed, None).await;
    assert_eq!(status, StatusCode::OK, "renewed token should work");

    // A fresh (full-life) token is not renewed.
    let fresh = backend::auth::issue_token(&env.email, "test-secret");
    let (status, headers, _) =
        do_json_with_headers(&env.router, "GET", "/api/me", &fresh, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers.get("X-Renewed-Token").is_none(),
        "full-life token should not renew"
    );

    // Hard expiry: past the window, the token is rejected outright.
    let expired = backend::auth::issue_token_with_ttl(&env.email, "test-secret", -60);
    let (status, body) = do_json(&env.router, "GET", "/api/me", &expired, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "expired token: {body}");

    env.cleanup().await;
}

// Full 2FA flow: new-device login demands a code, wrong codes are rejected,
// the emailed code yields a real JWT, the device is trusted from then on, and
// resend rotates the code.
#[tokio::test]
async fn two_factor_login() {
    let Some(env) = new_test_env().await else {
        return;
    };
    let (status, _) = do_json(
        &env.router,
        "POST",
        "/api/signup",
        "",
        Some(json!({ "email": &env.email, "password": &env.password })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "signup");

    // First login from an unknown device → 2FA required, no real JWT.
    let (status, body) = do_json(
        &env.router,
        "POST",
        "/api/login",
        "",
        Some(json!({
            "email": &env.email,
            "password": &env.password,
            "deviceId": "dev-1",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["twoFactorRequired"], json!(true), "{body}");
    let pending = body["token"].as_str().unwrap_or_default().to_string();
    assert!(
        !pending.is_empty(),
        "2FA login returned no pending token: {body}"
    );

    // Wrong code → 400, and the code stays pending.
    let (status, _) = do_json(
        &env.router,
        "POST",
        "/api/login/verify",
        "",
        Some(json!({ "token": &pending, "code": "0000", "deviceId": "dev-1" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "wrong code");

    // Resend rotates the code; the newest queued email wins.
    let (status, _) = do_json(
        &env.router,
        "POST",
        "/api/login/resend",
        "",
        Some(json!({ "token": &pending })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "resend");

    // Correct (resent) code → real JWT that works on /api/me.
    let (status, body) = do_json(
        &env.router,
        "POST",
        "/api/login/verify",
        "",
        Some(json!({
            "token": &pending,
            "code": fetch_login_code(&env.pool, &env.email).await,
            "deviceId": "dev-1",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "verify: {body}");
    let token = body["token"].as_str().unwrap_or_default().to_string();
    assert!(
        !token.is_empty() && token != pending,
        "verify returned no real token: {body}"
    );
    let (status, _) = do_json(&env.router, "GET", "/api/me", &token, None).await;
    assert_eq!(status, StatusCode::OK, "/api/me with 2FA token");

    // Same device again → 2FA skipped.
    let (status, body) = do_json(
        &env.router,
        "POST",
        "/api/login",
        "",
        Some(json!({
            "email": &env.email,
            "password": &env.password,
            "deviceId": "dev-1",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "trusted-device login: {body}");
    assert_ne!(body["twoFactorRequired"], json!(true), "{body}");
    let token2 = body["token"].as_str().unwrap_or_default().to_string();
    assert!(!token2.is_empty() && token2 != pending, "{body}");

    env.cleanup().await;
}
