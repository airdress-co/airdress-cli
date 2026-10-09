use anyhow::Result;

use super::storage;

pub fn run(paths: &crate::paths::Paths, name: Option<&str>, json: bool) -> Result<()> {
    let profile_name = storage::resolve_profile_name(paths, name)?;
    let profile = storage::read_profile(paths, &profile_name)?;

    let mut output = serde_json::json!({
        "profile": profile_name,
        "schema_version": profile.schema_version,
        "endpoint": profile.endpoint,
    });

    if let Some(auth) = &profile.auth {
        output["auth"] = storage::redact_auth(auth);
    } else {
        output["auth"] = serde_json::Value::Null;
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Profile:  {profile_name}");
        println!("Endpoint: {}", profile.endpoint);
        if let Some(auth) = &output["auth"].as_object() {
            println!(
                "Auth:     {}",
                auth.get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("none")
            );
        } else {
            println!("Auth:     none");
        }
    }
    Ok(())
}
