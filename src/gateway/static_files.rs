//! Static file serving for the embedded web dashboard.
//!
//! Uses `rust-embed` to bundle the `web/dist/` directory into the binary at compile time.

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use rust_embed::Embed;

use super::AppState;

#[derive(Embed)]
#[folder = "web/dist/"]
struct WebAssets;

/// Serve static files from `/_app/*` path
pub async fn handle_static(uri: Uri) -> Response {
    let path = uri
        .path()
        .strip_prefix("/_app/")
        .unwrap_or(uri.path())
        .trim_start_matches('/');

    serve_embedded_file(path)
}

/// SPA fallback: serve index.html for any non-API, non-static GET request.
/// Injects `window.__ZEROCLAW_BASE__` so the frontend knows the path prefix.
///
/// Prefix resolution order:
/// 1. Explicit `path_prefix` from config (highest priority)
/// 2. `X-Ingress-Path` header (set by Home Assistant ingress proxy)
/// 3. No prefix (default)
pub async fn handle_spa_fallback(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(content) = WebAssets::get("index.html") else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Web dashboard not available. Build it with: cd web && npm ci && npm run build",
        )
            .into_response();
    };

    let html = String::from_utf8_lossy(&content.data);

    // Resolve the effective prefix: config > X-Ingress-Path > none
    let ingress_prefix = if state.path_prefix.is_empty() {
        headers
            .get("X-Ingress-Path")
            .and_then(|v| v.to_str().ok())
            .and_then(sanitize_ingress_path)
    } else {
        None
    };

    let effective_prefix: &str = if state.path_prefix.is_empty() {
        ingress_prefix.as_deref().unwrap_or("")
    } else {
        &state.path_prefix
    };

    // Inject path prefix for the SPA and rewrite asset paths in the HTML
    let html = if effective_prefix.is_empty() {
        html.into_owned()
    } else {
        // JSON-encode the prefix to safely embed in a <script> block
        let json_pfx =
            serde_json::to_string(effective_prefix).unwrap_or_else(|_| "\"\"".to_string());
        let script = format!("<script>window.__ZEROCLAW_BASE__={json_pfx};</script>");
        // Rewrite absolute /_app/ references so the browser requests {prefix}/_app/...
        html.replace("/_app/", &format!("{effective_prefix}/_app/"))
            .replace("<head>", &format!("<head>{script}"))
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CACHE_CONTROL, "no-cache".to_string()),
        ],
        html,
    )
        .into_response()
}

/// Validate and sanitize an `X-Ingress-Path` header value.
/// Returns `None` if the value is empty, missing the leading `/`, or
/// contains characters unsafe for embedding in HTML/URLs.
fn sanitize_ingress_path(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() || !trimmed.starts_with('/') {
        return None;
    }
    // Same character allowlist as config path_prefix validation — reject
    // anything that could enable XSS or path traversal when injected into HTML.
    let safe = trimmed.chars().all(|c| {
        matches!(c, '/' | '-' | '_' | '.' | '~'
            | 'a'..='z' | 'A'..='Z' | '0'..='9'
            | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '='
            | ':' | '@')
    });
    if !safe {
        return None;
    }
    Some(trimmed.to_string())
}

fn serve_embedded_file(path: &str) -> Response {
    match WebAssets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();

            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, mime),
                    (
                        header::CACHE_CONTROL,
                        if path.contains("assets/") {
                            // Hashed filenames — immutable cache
                            "public, max-age=31536000, immutable".to_string()
                        } else {
                            // index.html etc — no cache
                            "no-cache".to_string()
                        },
                    ),
                ],
                content.data.to_vec(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_valid_ha_ingress_path() {
        assert_eq!(
            sanitize_ingress_path("/api/hassio_ingress/abc123"),
            Some("/api/hassio_ingress/abc123".into())
        );
    }

    #[test]
    fn sanitize_strips_trailing_slash() {
        assert_eq!(
            sanitize_ingress_path("/api/hassio_ingress/abc123/"),
            Some("/api/hassio_ingress/abc123".into())
        );
    }

    #[test]
    fn sanitize_strips_whitespace() {
        assert_eq!(sanitize_ingress_path("  /prefix  "), Some("/prefix".into()));
    }

    #[test]
    fn sanitize_rejects_empty() {
        assert_eq!(sanitize_ingress_path(""), None);
        assert_eq!(sanitize_ingress_path("   "), None);
    }

    #[test]
    fn sanitize_rejects_no_leading_slash() {
        assert_eq!(sanitize_ingress_path("api/ingress"), None);
    }

    #[test]
    fn sanitize_rejects_bare_slash() {
        // "/" becomes "" after trim_end_matches('/')
        assert_eq!(sanitize_ingress_path("/"), None);
    }

    #[test]
    fn sanitize_rejects_protocol_relative_url() {
        // "//evil.com" would produce protocol-relative asset URLs like
        // //evil.com/_app/foo.js, loading scripts from an external origin.
        assert_eq!(sanitize_ingress_path("//evil.com"), None);
        assert_eq!(sanitize_ingress_path("//evil.com/path"), None);
    }

    #[test]
    fn sanitize_rejects_xss_attempt() {
        assert_eq!(sanitize_ingress_path("/<script>alert(1)</script>"), None);
        assert_eq!(sanitize_ingress_path("/prefix?q=1"), None);
        assert_eq!(sanitize_ingress_path("/prefix#frag"), None);
        assert_eq!(sanitize_ingress_path("/pre fix"), None);
    }

    #[test]
    fn sanitize_allows_uri_safe_chars() {
        assert_eq!(
            sanitize_ingress_path("/a-b_c.d~e"),
            Some("/a-b_c.d~e".into())
        );
    }
}
