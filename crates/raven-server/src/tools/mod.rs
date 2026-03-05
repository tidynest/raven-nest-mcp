/// Returns true if the target URL points to a localhost address.
pub(crate) fn is_localhost(target: &str) -> bool {
    let lower = target.to_lowercase();
    let host_part = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
        .unwrap_or(&lower);
    host_part.starts_with("localhost")
        || host_part.starts_with("127.0.0.1")
        || host_part.starts_with("[::1]")
}

#[cfg(test)]
mod tests {
    use super::is_localhost;

    #[test]
    fn localhost_variants() {
        assert!(is_localhost("http://localhost:3000"));
        assert!(is_localhost("http://127.0.0.1:8080/path"));
        assert!(is_localhost("https://localhost/foo"));
        assert!(is_localhost("http://[::1]:3000"));
        assert!(is_localhost("localhost"));
    }

    #[test]
    fn remote_targets() {
        assert!(!is_localhost("http://example.com"));
        assert!(!is_localhost("https://10.0.0.1:443"));
        assert!(!is_localhost("hackthissite.org"));
    }
}

pub mod feroxbuster;
pub mod ffuf;
pub mod findings;
pub mod http;
pub mod hydra;
pub mod masscan;
pub mod nikto;
pub mod nmap;
pub mod nuclei;
pub mod ping;
pub mod scans;
pub mod sqlmap;
pub mod testssl;
pub mod whatweb;
