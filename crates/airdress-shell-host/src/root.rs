//! A host started as root says so, everywhere (D-15, FR-H8).
//!
//! It does not refuse: running as root is the person's choice. But every
//! session then runs as root, so the host prints a boxed warning at start,
//! and reports `runsAsRoot` so every client shows "This machine's shells run
//! as root" beside every profile.

/// Whether this process runs as root.
pub fn runs_as_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// The boxed warning printed at start.
pub fn banner() -> String {
    let lines = [
        "WARNING: this shell host runs as root.",
        "",
        "Every session it opens runs as root, for anyone who can",
        "open your shells from your devices. Your devices will show",
        "\"This machine's shells run as root\" beside every profile.",
        "",
        "Stop it (Ctrl-C) and start it as your own user unless",
        "root is really what you want.",
    ];
    let width = lines.iter().map(|l| l.chars().count()).max().unwrap_or(0);
    let mut s = format!("+{}+\n", "-".repeat(width + 2));
    for l in lines {
        s.push_str(&format!("| {l:<width$} |\n"));
    }
    s.push_str(&format!("+{}+", "-".repeat(width + 2)));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_banner_is_a_box_that_says_root() {
        let b = banner();
        let lines: Vec<&str> = b.lines().collect();
        assert!(lines[0].starts_with('+') && lines[0].ends_with('+'));
        assert!(lines
            .iter()
            .all(|l| l.chars().count() == lines[0].chars().count()));
        assert!(b.contains("runs as root"));
        assert!(b.contains("This machine's shells run as root"));
    }

    #[test]
    fn this_test_does_not_run_as_root() {
        // CI runs unprivileged; the host_info field follows the euid.
        assert_eq!(runs_as_root(), rustix::process::geteuid().as_raw() == 0);
    }
}
