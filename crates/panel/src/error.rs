//! Panel-wide error type. Small and direct — one enum used across db/api/auth.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug)]
pub enum PanelError {
    /// Database / persistence failure.
    Db(String),
    /// Requested entity not found.
    NotFound(String),
    /// Bad client input (validation).
    BadRequest(String),
    /// Auth failure (unauthenticated / bad credentials).
    Unauthorized,
    /// Password hashing/verification failure.
    Crypto(String),
    /// Internal/unexpected failure.
    Internal(String),
}

impl std::fmt::Display for PanelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PanelError::Db(m) => write!(f, "db error: {m}"),
            PanelError::NotFound(m) => write!(f, "not found: {m}"),
            PanelError::BadRequest(m) => write!(f, "bad request: {m}"),
            PanelError::Unauthorized => write!(f, "unauthorized"),
            PanelError::Crypto(m) => write!(f, "crypto error: {m}"),
            PanelError::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl std::error::Error for PanelError {}

impl From<sqlx::Error> for PanelError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => PanelError::NotFound("row".into()),
            other => PanelError::Db(other.to_string()),
        }
    }
}

impl IntoResponse for PanelError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            PanelError::NotFound(m) => (StatusCode::NOT_FOUND, m.clone()),
            PanelError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            PanelError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            PanelError::Db(m) | PanelError::Crypto(m) | PanelError::Internal(m) => {
                (StatusCode::INTERNAL_SERVER_ERROR, m.clone())
            }
        };
        let body = axum::Json(serde_json::json!({ "error": msg }));
        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, PanelError>;
