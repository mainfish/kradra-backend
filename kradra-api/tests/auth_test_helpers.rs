use reqwest::header::SET_COOKIE;

pub fn cookie_value_from_headers(headers: &reqwest::header::HeaderMap, name: &str) -> String {
    headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|raw| {
            raw.split(';')
                .next()
                .and_then(|first| first.split_once('='))
                .and_then(|(cookie_name, cookie_value)| {
                    if cookie_name == name {
                        Some(cookie_value.to_string())
                    } else {
                        None
                    }
                })
        })
        .unwrap_or_else(|| panic!("missing cookie {}", name))
}
