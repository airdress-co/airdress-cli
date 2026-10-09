//! What worked where: the transport hints, kept between runs.
//!
//! A network is named by a digest of the operator's origin and the prefix
//! of the local address the host reaches it from (a /24 or a /64). The file
//! therefore holds no address, and moving to another network starts from the
//! default order again. At most 16 networks are kept.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs as _};
use std::path::PathBuf;

use sha2::{Digest as _, Sha256};

use super::negotiate::Hint;

/// How many networks the file remembers.
pub const MAX_NETWORKS: usize = 16;

/// The hint file.
#[derive(Debug, Clone)]
pub struct HintFile {
    path: Option<PathBuf>,
}

impl HintFile {
    /// Hints kept at `path`.
    pub fn at(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    /// Hints kept nowhere (tests).
    pub fn none() -> Self {
        Self { path: None }
    }

    /// What is stored; nothing for a missing or malformed file.
    pub fn load(&self) -> BTreeMap<String, Hint> {
        self.path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Replace what is stored, the most recent [`MAX_NETWORKS`] only.
    pub fn save(&self, hints: &BTreeMap<String, Hint>) {
        let Some(p) = &self.path else { return };
        let mut v: Vec<(&String, &Hint)> = hints.iter().collect();
        v.sort_by(|a, b| b.1.since.total_cmp(&a.1.since));
        let kept: BTreeMap<&String, &Hint> = v.into_iter().take(MAX_NETWORKS).collect();
        if let Ok(mut bytes) = serde_json::to_vec_pretty(&kept) {
            bytes.push(b'\n');
            if let Err(e) = crate::paths::write_private_atomic(p, &bytes) {
                tracing::warn!(error = %e, "the transport hints could not be saved");
            }
        }
    }
}

/// Wall-clock seconds.
pub fn wall_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn prefix(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Ipv4Addr::new(o[0], o[1], o[2], 0).to_string() + "/24"
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0).to_string() + "/64"
        }
    }
}

fn local_prefix(origin: &str) -> Option<String> {
    let url: reqwest::Url = origin.parse().ok()?;
    let host = url.host_str()?.to_owned();
    let port = url.port_or_known_default()?;
    let addr = (host.as_str(), port).to_socket_addrs().ok()?.next()?;
    let bind = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    // A UDP "connect" sends nothing; it only asks the kernel for the route.
    let sock = std::net::UdpSocket::bind(bind).ok()?;
    sock.connect(addr).ok()?;
    Some(prefix(sock.local_addr().ok()?.ip()))
}

/// The key for "this network, towards this operator".
pub async fn network_key(origin: &str) -> String {
    let o = origin.to_owned();
    let p = tokio::task::spawn_blocking(move || local_prefix(&o))
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".into());
    let digest = Sha256::digest(format!("{origin}\u{1f}{p}").as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::negotiate::Transport;

    #[test]
    fn a_prefix_holds_no_host_part() {
        assert_eq!(prefix("203.0.113.77".parse().unwrap()), "203.0.113.0/24");
        assert_eq!(
            prefix("2001:db8:1:2:3:4:5:6".parse().unwrap()),
            "2001:db8:1:2::/64"
        );
    }

    #[tokio::test]
    async fn the_key_is_stable_and_holds_no_address() {
        let a = network_key("http://127.0.0.1:9").await;
        assert_eq!(a, network_key("http://127.0.0.1:9").await);
        assert_eq!(a.len(), 16);
        assert!(!a.contains("127"));
        assert_ne!(a, network_key("http://127.0.0.1:10").await);
    }

    #[test]
    fn hints_round_trip_and_keep_the_most_recent() {
        let d = tempfile::tempdir().unwrap();
        let f = HintFile::at(d.path().join("h.json"));
        let mut h = BTreeMap::new();
        for i in 0..20 {
            h.insert(
                format!("net{i:02}"),
                Hint {
                    transport: Transport::Poll,
                    since: f64::from(i),
                    preferred_failed: None,
                },
            );
        }
        f.save(&h);
        let back = f.load();
        assert_eq!(back.len(), MAX_NETWORKS);
        assert!(back.contains_key("net19") && !back.contains_key("net00"));
    }
}
