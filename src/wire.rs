//! Names the operator's API is addressed by, written once: the resource
//! plane's `apiVersion` and the functions routes. A route or a version
//! spelled inline is a second copy that can drift from this one (rust guide
//! R-TYP-6).

/// The `apiVersion` of every Kind this CLI writes (`Function`, `Home`, …).
pub const API_VERSION: &str = "airdress.co/v1alpha1";

/// The functions routes, under `/v1/functions`. Each takes already-escaped
/// path segments.
pub mod functions {
    /// `/v1/functions`.
    pub const ROOT: &str = "/v1/functions";
    /// `POST` publishes; `GET …/{version}` reads one stored version.
    pub const SOURCES: &str = "/v1/functions/sources";
    /// The templates the operator compiles in.
    pub const TEMPLATES: &str = "/v1/functions/templates";
    /// The Functions SDK catalogue.
    pub const SDK: &str = "/v1/functions/sdk";

    /// `/v1/functions/sources/{version}`.
    pub fn source(version: &str) -> String {
        format!("{SOURCES}/{version}")
    }

    /// `/v1/functions/templates/{id}`.
    pub fn template(id: &str) -> String {
        format!("{TEMPLATES}/{id}")
    }

    /// `/v1/functions/sdk/{version}`.
    pub fn sdk_release(version: &str) -> String {
        format!("{SDK}/{version}")
    }

    /// `/v1/functions/{name}/{leaf}`: `promote`, `versions`, `logs`.
    pub fn of(name: &str, leaf: &str) -> String {
        format!("{ROOT}/{name}/{leaf}")
    }
}

#[cfg(test)]
mod tests {
    use super::functions;

    #[test]
    fn the_routes_are_the_operators() {
        assert_eq!(
            functions::source("sha256:a"),
            "/v1/functions/sources/sha256:a"
        );
        assert_eq!(
            functions::template("hello"),
            "/v1/functions/templates/hello"
        );
        assert_eq!(functions::sdk_release("1.0.0"), "/v1/functions/sdk/1.0.0");
        assert_eq!(
            functions::of("relay", "promote"),
            "/v1/functions/relay/promote"
        );
    }
}
