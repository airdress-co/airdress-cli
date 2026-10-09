//! The panic hook for the long-running modes (R-ASY-8, amended).
//!
//! `panic = "abort"` is a property of a whole binary, and this binary is
//! also a CLI whose one-shot commands should print the report and exit
//! 101. So the modes that serve (`shell host`, `agent device serve`,
//! `mcp serve`) install this hook instead: a panic in any task prints the
//! usual report, is logged, and ends the process with a non-zero code.
//! Without it a panicked tokio task leaves the process "running as a
//! ghost": holding its lock or its socket, answering nothing.

/// The exit code of a serving mode that panicked (Rust's own for a panic).
pub const PANIC_EXIT: i32 = 101;

/// Install the hook for a serving mode named `mode` (for the log line).
pub fn install(mode: &'static str) {
    let report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // The standard report first (stderr; stdout may be a protocol).
        report(info);
        tracing::error!(mode, panic = %info, "a task panicked; the process exits");
        std::process::exit(PANIC_EXIT);
    }));
}
