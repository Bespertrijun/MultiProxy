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

#[cfg(test)]
mod tests {
    use super::INDEX_HTML;

    /// Every top-level renderer must be invoked *directly* from `renderAll()`.
    ///
    /// Regression guard for two shipped bugs of the same shape: a container kept
    /// its hardcoded "正在加载…" placeholder forever because the function that
    /// fills it was never reached. v0.10.5: the whole render pass only ran when
    /// the fetched data *changed*, so an empty DB never rendered. v0.10.6:
    /// `renderTopology()` hung off the tail of `renderDashboard()`, which returns
    /// early when the node list is empty — so 链路总览 stayed on "正在加载..."
    /// even though the other four containers had been fixed.
    ///
    /// The lesson this locks: chaining a renderer behind another renderer's
    /// early-return path is what breaks empty/error states. Keep all five calls
    /// unconditional in `renderAll`.
    #[test]
    fn render_all_invokes_every_top_level_renderer() {
        let start = INDEX_HTML
            .find("function renderAll()")
            .expect("renderAll() must exist in the frontend");
        let body_start = start
            + INDEX_HTML[start..]
                .find('{')
                .expect("renderAll() must have a body");
        // The body ends at the first column-0 `}` — renderAll has no nested blocks.
        let body_end = body_start
            + INDEX_HTML[body_start..]
                .find("\n}")
                .expect("renderAll() must be closed");
        // Drop `//` comments so prose mentioning a renderer can't mask a call that
        // was actually deleted.
        let body: String = INDEX_HTML[body_start..body_end]
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        for call in [
            "renderDashboard()",
            "renderTopology()",
            "renderNodes()",
            "renderZones()",
            "renderSettings()",
        ] {
            assert!(
                body.contains(call),
                "renderAll() must call {call} directly — not nested behind another \
                 renderer, whose early return would skip it and strand a \
                 \"正在加载…\" placeholder. renderAll body was:\n{body}"
            );
        }
    }
}
