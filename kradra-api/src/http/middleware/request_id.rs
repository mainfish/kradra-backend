use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderName, HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;
use std::net::SocketAddr;

const REQUEST_ID_HEADER: &str = "x-request-id";
const CLIENT_IP_HEADER: &str = "x-client-ip";

fn generate_request_id() -> String {
    use rand_core::{OsRng, RngCore};

    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);

    // UUID v4:
    // - version nibble = 4
    // - variant = 10xxxxxx
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn is_valid_request_id(request_id: &str) -> bool {
    let bytes = request_id.as_bytes();

    // UUID canonical form: 8-4-4-4-12 => 36 chars
    if bytes.len() != 36 {
        return false;
    }

    // Hyphen positions
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return false;
    }

    // All other positions must be hex
    for (index, byte) in bytes.iter().enumerate() {
        let is_hyphen_position = matches!(index, 8 | 13 | 18 | 23);

        if is_hyphen_position {
            continue;
        }

        if !is_hex(*byte) {
            return false;
        }
    }

    // UUID version must be 4  => xxxxxxxx-xxxx-4xxx-....
    if bytes[14] != b'4' {
        return false;
    }

    // UUID variant must be 8, 9, a, or b => xxxxxxxx-xxxx-xxxx-[89ab]xxx-....
    matches!(bytes[19], b'8' | b'9' | b'a' | b'b' | b'A' | b'B')
}

fn first_ip_from_x_forwarded_for(value: &str) -> Option<String> {
    // Format: client, proxy1, proxy2
    let first = value.split(',').next()?.trim();
    if first.is_empty() {
        return None;
    }

    // Strip optional port
    let ip_only = first.split(':').next().unwrap_or(first).trim();
    if ip_only.is_empty() {
        return None;
    }

    Some(ip_only.to_string())
}

fn ip_from_forwarded_header(value: &str) -> Option<String> {
    // Tiny parser for RFC 7239 Forwarded: for=1.2.3.4;proto=https;by=...
    for part in value.split(';') {
        let part = part.trim();

        if let Some(rest) = part.strip_prefix("for=") {
            let for_value = rest.trim().trim_matches('"');

            // IPv6 may be in brackets: for="[2001:db8::1]"
            if let Some(stripped) = for_value.strip_prefix('[') {
                if let Some(end) = stripped.find(']') {
                    return Some(stripped[..end].to_string());
                }
            }

            // Strip optional port
            let ip_only = for_value.split(':').next().unwrap_or(for_value).trim();
            if !ip_only.is_empty() {
                return Some(ip_only.to_string());
            }
        }
    }

    None
}

fn extract_client_ip_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    // Prefer standard proxy headers.
    if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(ip) = first_ip_from_x_forwarded_for(value) {
            return Some(ip);
        }
    }

    if let Some(value) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let ip = value.trim();
        if !ip.is_empty() {
            return Some(ip.to_string());
        }
    }

    if let Some(value) = headers.get("forwarded").and_then(|v| v.to_str().ok()) {
        if let Some(ip) = ip_from_forwarded_header(value) {
            return Some(ip);
        }
    }

    None
}

pub async fn client_ip(mut req: Request<Body>, next: Next) -> Response {
    let header_name = HeaderName::from_static(CLIENT_IP_HEADER);

    // If already set by an upstream proxy/middleware, keep it.
    let mut client_ip = req
        .headers()
        .get(&header_name)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    if client_ip.is_none() {
        client_ip = extract_client_ip_from_headers(req.headers());
    }

    if client_ip.is_none() {
        // Fallback to socket peer addr when running without a proxy.
        if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
            client_ip = Some(addr.ip().to_string());
        }
    }

    if let Some(ip) = client_ip {
        if let Ok(value) = HeaderValue::from_str(&ip) {
            req.headers_mut().insert(header_name, value);
        }
    }

    next.run(req).await
}

pub async fn request_id(mut req: Request<Body>, next: Next) -> Response {
    let header_name = HeaderName::from_static(REQUEST_ID_HEADER);

    let request_id = req
        .headers()
        .get(&header_name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| is_valid_request_id(value))
        .unwrap_or_else(generate_request_id);

    if let Ok(header_value) = HeaderValue::from_str(&request_id) {
        req.headers_mut().insert(header_name.clone(), header_value);
    }

    let mut response = next.run(req).await;

    if let Ok(header_value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(header_name, header_value);
    }

    response
}
