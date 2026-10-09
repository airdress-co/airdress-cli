//! Discarding a `Result` is a decision, and this is how it is written down.
//!
//! `let _ = op();` hides whether the author thought about the failure at
//! all. `op().log_warn("…")` says the failure degrades something and the
//! caller carries on; `op().log_debug("…")` says the failure is the normal
//! end of something (a receiver that went away at shutdown, a peer that
//! hung up first). Either way the failure leaves a line.
//!
//! What is said is a short phrase naming the operation, never a secret:
//! the error is logged with its alternate `Display` (`{:#}`, which is the
//! whole chain for an `anyhow::Error`), so an error must not carry one
//! either.

use std::fmt::Display;

/// [`LogErr::log_warn`] and [`LogErr::log_debug`] on any `Result` whose
/// error can be displayed.
pub trait LogErr {
    /// A failure that degrades something the caller then works around.
    fn log_warn(self, what: &str);
    /// A failure that is the expected end of something.
    fn log_debug(self, what: &str);
}

impl<T, E: Display> LogErr for Result<T, E> {
    fn log_warn(self, what: &str) {
        if let Err(e) = self {
            tracing::warn!(error = %format_args!("{e:#}"), "{what} failed");
        }
    }

    fn log_debug(self, what: &str) {
        if let Err(e) = self {
            tracing::debug!(error = %format_args!("{e:#}"), "{what} failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_and_err_both_return_unit() {
        Ok::<u8, String>(1).log_warn("nothing");
        Err::<u8, String>("boom".into()).log_warn("the thing");
        Err::<u8, std::io::Error>(std::io::ErrorKind::NotFound.into()).log_debug("a read");
    }
}
