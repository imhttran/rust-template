// Port of mail.go — the email templates plus the mailer: real SMTP when
// SMTP_HOST is set, otherwise the email is logged instead of sent, so dev
// works with no mail server.

use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::config::Config;

pub struct EmailData {
    pub to: String,
    pub subject: String,
    pub body: String,
}

// Build the welcome-email row data; used so the enqueue is atomic with the user create.
pub fn welcome_email(to: &str) -> EmailData {
    EmailData {
        to: to.to_string(),
        subject: "Your account has been created".to_string(),
        body: "Hi,\n\nYou've been successfully added to our system.\n\nThanks,\nThe Team"
            .to_string(),
    }
}

// Build the verification-email row data with the click-to-verify link.
pub fn verification_email(to: &str, link: &str) -> EmailData {
    EmailData {
        to: to.to_string(),
        subject: "Verify your email address".to_string(),
        body: format!(
            "Hi,\n\nPlease verify your email address by visiting this link:\n\n{link}\n\nThanks,\nThe Team"
        ),
    }
}

// Build the password-reset email row data with the click-to-reset link.
pub fn password_reset_email(to: &str, link: &str) -> EmailData {
    EmailData {
        to: to.to_string(),
        subject: "Reset your password".to_string(),
        body: format!(
            "Hi,\n\nA password reset was requested for this account. Click the link below to choose a new password (expires in 1 hour):\n\n{link}\n\nIf you didn't request this, you can ignore this email.\n\nThanks,\nThe Team"
        ),
    }
}

// Build the 2FA login-code email row data.
pub fn login_code_email(to: &str, code: &str) -> EmailData {
    EmailData {
        to: to.to_string(),
        subject: "Your login code".to_string(),
        body: format!(
            "Hi,\n\nYour login verification code is:\n\n{code}\n\nIt expires in 10 minutes.\n\nThanks,\nThe Team"
        ),
    }
}

// Next.js client routes (no .html).
pub fn token_link(frontend_url: &str, page: &str, token: &str) -> String {
    format!("{frontend_url}/{page}?token={token}")
}

// Enqueue an email row. Generic so callers can enqueue inside a transaction
// or straight on the pool.
pub async fn enqueue_email<'e, E>(db: E, row: &EmailData) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query("INSERT INTO email_queue (\"to\", subject, body) VALUES ($1, $2, $3)")
        .bind(&row.to)
        .bind(&row.subject)
        .bind(&row.body)
        .execute(db)
        .await
        .map(|_| ())
}

static LOG_TRANSPORT_NOTICE: std::sync::Once = std::sync::Once::new();

// Send one email: real SMTP when SMTP_HOST is set (implicit TLS on :465,
// opportunistic STARTTLS otherwise, plain auth when credentials are set),
// otherwise log the email instead of sending — dev needs no mail server.
pub async fn send_mail(cfg: &Config, to: &str, subject: &str, text: &str) -> Result<(), String> {
    if cfg.smtp_host.is_empty() {
        LOG_TRANSPORT_NOTICE.call_once(|| {
            eprintln!("[mailer] SMTP_HOST not set — emails are logged, not sent.");
        });
        println!(
            "[mailer] email: {}",
            serde_json::json!({
                "from": cfg.mail_from,
                "to": to,
                "subject": subject,
                "text": text,
            })
        );
        return Ok(());
    }
    if (to.to_string() + subject + &cfg.mail_from)
        .chars()
        .any(|c| c == '\r' || c == '\n')
    {
        return Err("invalid header characters in email".to_string());
    }
    let from: lettre::message::Mailbox = cfg
        .mail_from
        .parse::<lettre::message::Mailbox>()
        .map_err(|e| e.to_string())?;
    let recipient: lettre::message::Mailbox = to
        .parse::<lettre::message::Mailbox>()
        .map_err(|e| e.to_string())?;
    let email = Message::builder()
        .from(from)
        .to(recipient)
        .subject(subject.to_string())
        .body(text.to_string())
        .map_err(|e| e.to_string())?;

    let builder = if cfg.smtp_port == 465 {
        // Implicit TLS, like Go's tls.Dial + smtp.NewClient.
        AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_host).map_err(|e| e.to_string())?
    } else {
        // Opportunistic STARTTLS, like nodemailer's (and Go's) default.
        let tls = TlsParameters::builder(cfg.smtp_host.clone())
            .build()
            .map_err(|e| e.to_string())?;
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_host)
            .port(cfg.smtp_port)
            .tls(Tls::Opportunistic(tls))
    };
    let builder = if cfg.smtp_user.is_empty() {
        builder
    } else {
        builder.credentials(Credentials::new(
            cfg.smtp_user.clone(),
            cfg.smtp_pass.clone(),
        ))
    };
    builder
        .build()
        .send(email)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
