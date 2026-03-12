use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderName, HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;
use std::net::SocketAddr;

const REQUEST_ID_HEADER: &str = "x-request-id";
const CLIENT_IP_HEADER: &str = "x-client-ip";

fn trust_proxy_headers() -> bool {
    std::env::var("TRUST_PROXY_HEADERS")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn is_trusted_proxy_ip(peer_ip: &str) -> bool {
    let list = std::env::var("TRUSTED_PROXY_IPS").unwrap_or_default();

    for item in list.split(',') {
        let ip = item.trim();
        if !ip.is_empty() && ip == peer_ip {
            return true;
        }
    }

    false
}

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

pub async fn client_ip(mut req: Request<Body>, next: Next) -> Response {
    let header_name = HeaderName::from_static(CLIENT_IP_HEADER);

    // Peer ip from socket (requires ConnectInfo enabled in main).
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string());

    let mut client_ip: Option<String> = None;

    // Trust X-Real-IP only when request comes from a trusted proxy.
    if trust_proxy_headers() {
        if let Some(peer_ip_value) = &peer_ip {
            if is_trusted_proxy_ip(peer_ip_value) {
                if let Some(value) = req.headers().get("x-real-ip").and_then(|v| v.to_str().ok()) {
                    let ip = value.trim();
                    if !ip.is_empty() {
                        client_ip = Some(ip.to_string());
                    }
                }
            }
        }
    }

    // Fallback: always use peer ip.
    if client_ip.is_none() {
        client_ip = peer_ip;
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
