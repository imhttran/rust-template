use std::sync::Arc;

use sqlx::PgPool;

use crate::config::Config;

// Shared handler state — replaces the Go globals (cfg, db). PgPool is an Arc
// internally, so cloning AppState is cheap.
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub db: PgPool,
}
