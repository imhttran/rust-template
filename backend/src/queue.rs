// Port of queue.go — the DB-backed queue enqueue helpers. The polling worker
// lands with the mailer in Phase 5.

use std::fmt;
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use sqlx::PgPool;

use crate::auth::random_token;
use crate::mail::{self, token_link};
use crate::state::AppState;

// Prisma's P2025 (record not found in an update) as a sentinel.
pub enum QueueError {
    NotFound,
    Db(sqlx::Error),
}

impl fmt::Display for QueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueueError::NotFound => write!(f, "user not found"),
            QueueError::Db(err) => write!(f, "{err}"),
        }
    }
}

const RESET_TOKEN_TTL_HOURS: i64 = 1;

// Keyed by email (self-service forgot-password) or id (admin-triggered reset).
pub enum ResetKey {
    Email(String),
    Id(i32),
}

// Shared by /api/forgot-password and the admin-triggered reset route. One
// transaction: the update itself both finds the user (NotFound if it doesn't
// match) and sets the token, so callers don't need their own lookup+404 check.
pub async fn queue_password_reset(
    db: &PgPool,
    frontend_url: &str,
    key: ResetKey,
) -> Result<(), QueueError> {
    let token = random_token();
    let mut tx = db.begin().await.map_err(QueueError::Db)?;
    let expiry = chrono::Utc::now() + ChronoDuration::hours(RESET_TOKEN_TTL_HOURS);
    let found: Option<String> = match key {
        ResetKey::Email(email) => {
            sqlx::query_scalar(
                "UPDATE users SET reset_token = $1, reset_token_expiry = $2
                 WHERE email = $3
                 RETURNING email",
            )
            .bind(&token)
            .bind(expiry)
            .bind(email)
            .fetch_optional(&mut *tx)
            .await
        }
        ResetKey::Id(id) => {
            sqlx::query_scalar(
                "UPDATE users SET reset_token = $1, reset_token_expiry = $2
                 WHERE id = $3
                 RETURNING email",
            )
            .bind(&token)
            .bind(expiry)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
        }
    }
    .map_err(QueueError::Db)?;
    let Some(email) = found else {
        return Err(QueueError::NotFound);
    };
    let row =
        mail::password_reset_email(&email, &token_link(frontend_url, "reset-password", &token));
    mail::enqueue_email(&mut *tx, &row)
        .await
        .map_err(QueueError::Db)?;
    tx.commit().await.map_err(QueueError::Db)?;
    Ok(())
}

// Shared by /api/resend-verification (self-service) and the staff-triggered resend route.
pub async fn queue_verification_email(
    db: &PgPool,
    frontend_url: &str,
    user_id: i32,
    email: &str,
) -> Result<(), QueueError> {
    let token = random_token();
    let mut tx = db.begin().await.map_err(QueueError::Db)?;
    sqlx::query("UPDATE users SET verification_token = $1 WHERE id = $2")
        .bind(&token)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(QueueError::Db)?;
    let row = mail::verification_email(email, &token_link(frontend_url, "verify", &token));
    mail::enqueue_email(&mut *tx, &row)
        .await
        .map_err(QueueError::Db)?;
    tx.commit().await.map_err(QueueError::Db)?;
    Ok(())
}

// Pick up pending emails, send them, mark sent / retry with a bounded cap.
// Returns the number of jobs processed (used by tests).
pub async fn process_email_queue(state: &AppState, take: i32) -> usize {
    let rows: Result<Vec<(i32, String, String, String, i32)>, _> = sqlx::query_as(
        "SELECT id, \"to\", subject, body, attempts
         FROM email_queue
         WHERE status = 'pending' AND attempts < $1
         ORDER BY created_at ASC
         LIMIT $2",
    )
    .bind(state.cfg.max_attempts)
    .bind(take)
    .fetch_all(&state.db)
    .await;
    let jobs = match rows {
        Ok(jobs) => jobs,
        Err(err) => {
            eprintln!("[emailQueue] worker error: {err}");
            return 0;
        }
    };
    for (id, to, subject, body, attempts) in &jobs {
        match mail::send_mail(&state.cfg, to, subject, body).await {
            Err(err) => {
                let attempts = attempts + 1;
                let status = if attempts >= state.cfg.max_attempts {
                    "failed"
                } else {
                    "pending"
                };
                // ponytail: no backoff; fixed-interval poll is the retry. Add exponential backoff if a slow mailer causes stampedes.
                let _ = sqlx::query(
                    "UPDATE email_queue SET attempts = $1, last_error = $2, status = $3 WHERE id = $4",
                )
                .bind(attempts)
                .bind(&err)
                .bind(status)
                .bind(id)
                .execute(&state.db)
                .await;
            }
            Ok(()) => {
                let _ = sqlx::query(
                    "UPDATE email_queue SET status = 'sent', sent_at = now() WHERE id = $1",
                )
                .bind(id)
                .execute(&state.db)
                .await;
            }
        }
    }
    jobs.len()
}

// Polling worker.
pub async fn start_email_worker(state: AppState) {
    let mut ticker = tokio::time::interval(Duration::from_secs(3));
    loop {
        ticker.tick().await;
        process_email_queue(&state, 10).await;
    }
}
