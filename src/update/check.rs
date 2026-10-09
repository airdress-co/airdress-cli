use anyhow::{bail, Context, Result};

const INDEX_URL: &str = "https://downloads.airdress.co/airdress-cli/index.json";

#[derive(Debug, serde::Deserialize)]
pub struct VersionIndex {
    #[allow(dead_code)]
    pub schema_version: u32,
    pub versions: Vec<String>,
    pub latest: Option<String>,
    pub latest_stable: Option<String>,
}

pub async fn fetch_index(client: &reqwest::Client) -> Result<VersionIndex> {
    client
        .get(INDEX_URL)
        .send()
        .await
        .context("failed to fetch version index")?
        .error_for_status()
        .context("version index returned an error")?
        .json()
        .await
        .context("failed to parse version index")
}

pub fn resolve_target_version(
    index: &VersionIndex,
    current: &str,
    pinned: Option<&str>,
    prerelease: bool,
) -> Result<Option<String>> {
    let target = if let Some(v) = pinned {
        if !index.versions.contains(&v.to_string()) {
            let available = index.versions.join(", ");
            bail!("version {v} not found. Available: {available}");
        }
        v.to_string()
    } else if prerelease {
        index.latest.clone().unwrap_or_default()
    } else {
        index
            .latest_stable
            .clone()
            .or_else(|| index.latest.clone())
            .unwrap_or_default()
    };

    if target.is_empty() {
        bail!("no release version available");
    }

    let current_normalized = current.strip_prefix('v').unwrap_or(current);
    let target_normalized = target.strip_prefix('v').unwrap_or(&target);

    if current_normalized == target_normalized {
        return Ok(None);
    }

    Ok(Some(target))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_index(latest: &str, latest_stable: Option<&str>, versions: Vec<&str>) -> VersionIndex {
        VersionIndex {
            schema_version: 1,
            versions: versions.into_iter().map(String::from).collect(),
            latest: Some(latest.to_string()),
            latest_stable: latest_stable.map(String::from),
        }
    }

    #[test]
    fn test_resolves_latest_stable() {
        let index = make_index(
            "v0.3.0-rc.1",
            Some("v0.2.0"),
            vec!["v0.1.0", "v0.2.0", "v0.3.0-rc.1"],
        );
        let result = resolve_target_version(&index, "0.1.0", None, false).unwrap();
        assert_eq!(result, Some("v0.2.0".to_string()));
    }

    #[test]
    fn test_fallback_to_latest_when_no_stable() {
        let index = make_index("v0.2.0", None, vec!["v0.1.0", "v0.2.0"]);
        let result = resolve_target_version(&index, "0.1.0", None, false).unwrap();
        assert_eq!(result, Some("v0.2.0".to_string()));
    }

    #[test]
    fn test_prerelease_picks_latest() {
        let index = make_index(
            "v0.3.0-rc.1",
            Some("v0.2.0"),
            vec!["v0.1.0", "v0.2.0", "v0.3.0-rc.1"],
        );
        let result = resolve_target_version(&index, "0.1.0", None, true).unwrap();
        assert_eq!(result, Some("v0.3.0-rc.1".to_string()));
    }

    #[test]
    fn test_pinned_valid() {
        let index = make_index("v0.2.0", Some("v0.2.0"), vec!["v0.1.0", "v0.1.5", "v0.2.0"]);
        let result = resolve_target_version(&index, "0.1.0", Some("v0.1.5"), false).unwrap();
        assert_eq!(result, Some("v0.1.5".to_string()));
    }

    #[test]
    fn test_pinned_invalid() {
        let index = make_index("v0.2.0", Some("v0.2.0"), vec!["v0.1.0", "v0.2.0"]);
        let err = resolve_target_version(&index, "0.1.0", Some("v0.9.9"), false).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_already_up_to_date() {
        let index = make_index("v0.2.0", Some("v0.2.0"), vec!["v0.1.0", "v0.2.0"]);
        let result = resolve_target_version(&index, "0.2.0", None, false).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_pinned_equals_current() {
        let index = make_index("v0.2.0", Some("v0.2.0"), vec!["v0.1.0", "v0.2.0"]);
        let result = resolve_target_version(&index, "0.1.0", Some("v0.1.0"), false).unwrap();
        assert_eq!(result, None);
    }
}
