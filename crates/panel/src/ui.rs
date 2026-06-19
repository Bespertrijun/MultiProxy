//! Embedded minimal HTML/JS management UI (Line A task 3/7 / AC-9 panel side) via
//! rust-embed. The `frontend/` directory is baked into the binary at compile time.

use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "frontend/"]
struct Assets;

/// Serve an embedded static asset under `/ui/*`.
pub async fn static_handler(Path(path): Path<String>) -> Response {
    match Assets::get(&path) {
        Some(content) => {
            let mime = mime_for(&path);
            ([(header::CONTENT_TYPE, mime)], content.data.into_owned()).into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

fn mime_for(path: &str) -> &'static str {
    if path.ends_with(".js") {
        "application/javascript"
    } else if path.ends_with(".css") {
        "text/css"
    } else if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

/// The inline index page (kept inline so the panel serves a working UI even with an
/// empty `frontend/` dir). It drives the CRUD + login + health APIs.
pub const INDEX_HTML: &str = include_str!("../frontend/index.html");
