use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;
use tokio::task::JoinSet;

use crate::profile::storage;
use crate::redact::Redacted;

use super::client::{Airdress, HubClient};

const PROBE_TIMEOUT_SECS: u64 = 5;
const PROBE_CONNECT_TIMEOUT_SECS: u64 = 3;

pub async fn run(
    paths: &crate::paths::Paths,
    profile_name: Option<&str>,
    json: bool,
) -> Result<()> {
    let name = storage::resolve_profile_name(paths, profile_name)?;
    let client = HubClient::from_profile(paths, &name).await?;
    let items = client.list().await?;
    let pings = probe_all(&client, &items).await;
    print(paths, &name, &items, &pings, json)?;
    Ok(())
}

#[derive(Debug, serde::Deserialize)]
struct ProbeResponse {
    transport: String,
    #[serde(default)]
    via_relay: Option<bool>,
}

async fn probe_one(endpoint: String, id: String, bearer: Redacted<String>) -> (String, String) {
    // A probe per airdress, side by side: short deadlines, never longer
    // than `--timeout`, and the TLS settings every other client has.
    let client = crate::http::client_with(crate::http::Timeouts {
        connect: Duration::from_secs(PROBE_CONNECT_TIMEOUT_SECS),
        ..crate::http::Timeouts::at_most(Duration::from_secs(PROBE_TIMEOUT_SECS))
    })
    .build();
    let client = match client {
        Ok(c) => c,
        Err(_) => return (id, "—".into()),
    };
    let url = format!(
        "{}/api/airdresses/{}/probe",
        endpoint.trim_end_matches('/'),
        id
    );
    let resp = match client.get(&url).bearer_auth(bearer.expose()).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return (id, "—".into()),
    };
    match resp.json::<ProbeResponse>().await {
        Ok(body) => {
            let label = match (body.transport.as_str(), body.via_relay) {
                ("ipv6", _) => "direct-v6",
                ("ipv4", Some(false)) => "direct-v4",
                ("ipv4", _) => "relay",
                _ => "down",
            };
            (id, label.into())
        }
        Err(_) => (id, "—".into()),
    }
}

async fn probe_all(client: &HubClient, items: &[Airdress]) -> HashMap<String, String> {
    if items.is_empty() {
        return HashMap::new();
    }
    let endpoint = client.endpoint().to_string();
    let bearer = client.bearer().clone();

    let mut set = JoinSet::new();
    for a in items {
        let ep = endpoint.clone();
        let id = a.id.clone();
        let tok = bearer.clone();
        set.spawn(probe_one(ep, id, tok));
    }

    let mut results = HashMap::with_capacity(items.len());
    while let Some(Ok((id, status))) = set.join_next().await {
        results.insert(id, status);
    }
    results
}

fn print(
    paths: &crate::paths::Paths,
    profile_name: &str,
    items: &[Airdress],
    pings: &HashMap<String, String>,
    json: bool,
) -> Result<()> {
    if json {
        // SPEC-043 — envelope shape: {"profile": "...", "airdresses": [...]}.
        // Breaking change from the bare-array v0 shape. The active
        // airdress (if any) for this profile is included so callers
        // (status pages, prompts) get the resolved context in one
        // call.
        let enriched: Vec<serde_json::Value> = items
            .iter()
            .map(|a| {
                let mut v = serde_json::to_value(a).unwrap();
                if let Some(p) = pings.get(&a.id) {
                    v.as_object_mut()
                        .unwrap()
                        .insert("ping".into(), serde_json::Value::String(p.clone()));
                }
                v
            })
            .collect();
        let active = storage::read_profile(paths, profile_name)
            .ok()
            .and_then(|p| p.active_airdress);
        let envelope = serde_json::json!({
            "profile": profile_name,
            "active_airdress": active,
            "airdresses": enriched,
        });
        println!("{}", serde_json::to_string_pretty(&envelope)?);
        return Ok(());
    }
    if items.is_empty() {
        println!("(no airdresses)");
        return Ok(());
    }
    let widths = column_widths(items, pings);
    print_row(
        &widths,
        [
            "NAME", "LABEL", "FQDN", "IPV4", "IPV6", "STATUS", "PING", "COMMENT", "CREATED", "ID",
        ],
    );
    for a in items {
        let ping = pings.get(&a.id).map(|s| s.as_str()).unwrap_or("—");
        print_row(
            &widths,
            [
                a.name.as_str(),
                a.label.as_deref().unwrap_or(""),
                a.fqdn.as_str(),
                a.ipv4_address.as_str(),
                a.ipv6_address.as_deref().unwrap_or("—"),
                a.status.as_str(),
                ping,
                a.comment.as_deref().unwrap_or(""),
                a.created_at.as_str(),
                a.id.as_str(),
            ],
        );
    }
    Ok(())
}

#[derive(Debug)]
struct Widths {
    name: usize,
    label: usize,
    fqdn: usize,
    ipv4: usize,
    ipv6: usize,
    status: usize,
    ping: usize,
    comment: usize,
    created: usize,
    id: usize,
}

fn column_widths(items: &[Airdress], pings: &HashMap<String, String>) -> Widths {
    let mut w = Widths {
        name: "NAME".len(),
        label: "LABEL".len(),
        fqdn: "FQDN".len(),
        ipv4: "IPV4".len(),
        ipv6: "IPV6".len(),
        status: "STATUS".len(),
        ping: "PING".len(),
        comment: "COMMENT".len(),
        created: "CREATED".len(),
        id: "ID".len(),
    };
    for a in items {
        w.name = w.name.max(a.name.len());
        w.label = w.label.max(a.label.as_deref().map_or(0, str::len));
        w.fqdn = w.fqdn.max(a.fqdn.len());
        w.ipv4 = w.ipv4.max(a.ipv4_address.len());
        w.ipv6 = w.ipv6.max(a.ipv6_address.as_deref().map_or(1, str::len));
        w.status = w.status.max(a.status.len());
        w.ping = w.ping.max(pings.get(&a.id).map(|s| s.len()).unwrap_or(1));
        w.comment = w.comment.max(a.comment.as_deref().map_or(0, str::len));
        w.created = w.created.max(a.created_at.len());
        w.id = w.id.max(a.id.len());
    }
    w
}

fn print_row(w: &Widths, cells: [&str; 10]) {
    println!(
        "{:<nw$}  {:<lw$}  {:<fw$}  {:<v4w$}  {:<v6w$}  {:<sw$}  {:<pw$}  {:<cow$}  {:<cw$}  {}",
        cells[0],
        cells[1],
        cells[2],
        cells[3],
        cells[4],
        cells[5],
        cells[6],
        cells[7],
        cells[8],
        cells[9],
        nw = w.name,
        lw = w.label,
        fw = w.fqdn,
        v4w = w.ipv4,
        v6w = w.ipv6,
        sw = w.status,
        pw = w.ping,
        cow = w.comment,
        cw = w.created,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_grow_to_longest_value() {
        let items = vec![Airdress {
            id: "01HVERYLONGIDENTIFIER".into(),
            name: "alice".into(),
            fqdn: "01h.a.airdr.es".into(),
            ipv4_address: "23.163.148.11".into(),
            ipv6_address: Some("2001:db8::1".into()),
            label: Some("Home server".into()),
            comment: Some("Main box".into()),
            status: "DnsActive".into(),
            created_at: "2026-05-15T08:00:00Z".into(),
        }];
        let pings = HashMap::from([("01HVERYLONGIDENTIFIER".into(), "direct-v6".into())]);
        let w = column_widths(&items, &pings);
        assert_eq!(w.id, "01HVERYLONGIDENTIFIER".len());
        assert_eq!(w.status, "DnsActive".len());
        assert_eq!(w.ipv6, "2001:db8::1".len());
        assert_eq!(w.ping, "direct-v6".len());
        assert_eq!(w.label, "Home server".len());
        assert_eq!(w.comment, "Main box".len());
    }

    #[test]
    fn widths_default_ping_dash() {
        let items = vec![Airdress {
            id: "01HXXX".into(),
            name: "bob".into(),
            fqdn: "01h.a.airdr.es".into(),
            ipv4_address: "23.163.148.11".into(),
            ipv6_address: None,
            label: None,
            comment: None,
            status: "DnsActive".into(),
            created_at: "2026-05-15T08:00:00Z".into(),
        }];
        let pings = HashMap::new();
        let w = column_widths(&items, &pings);
        assert_eq!(w.ping, "PING".len());
        assert_eq!(w.label, "LABEL".len());
        assert_eq!(w.comment, "COMMENT".len());
    }
}
