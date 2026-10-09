//! SPEC-044 — pairing-completion watcher.
//!
//! Polls the operator's `/v1/endpoints/pairing-codes/{id}` endpoint
//! every ~3 seconds (with jitter) until one of:
//!
//! - `Consumed(device)` — the phone scanned and enrollment finished.
//! - `Expired` — the operator says the 5-minute TTL elapsed.
//! - Wall-clock cap — we stop polling at `expires_at + grace`.
//! - Ctrl-C — the caller's cancellation token fires.
//!
//! v1 ships polling only. SSE is deferred to SPEC-044.1.

use anyhow::Result;
use chrono::{DateTime, Utc};
use rand::Rng;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use super::client::{OperatorEnrollClient, PairedDevice, PairingPollResult};

const POLL_INTERVAL: Duration = Duration::from_secs(3);
const JITTER_MS: u64 = 500;
const POST_EXPIRY_GRACE: Duration = Duration::from_secs(5);

/// Outcome of a wait.
#[derive(Debug)]
pub enum WaitOutcome {
    Paired(PairedDevice),
    Expired,
    Cancelled,
}

/// Poll the operator for pairing completion until done, expired, or
/// cancelled.
///
/// `cancel` lets the caller bail (Ctrl-C) without leaving an HTTP
/// request in flight beyond the next poll cycle.
///
/// # Errors
///
/// Only returns `Err` on persistent transport / server errors. Single
/// transient network errors are logged at debug and retried after the
/// next poll interval.
pub async fn wait_for_completion(
    op: &OperatorEnrollClient,
    pairing_code_id: uuid::Uuid,
    expires_at: DateTime<Utc>,
    cancel: CancellationToken,
) -> Result<WaitOutcome> {
    let deadline = expires_at + chrono::Duration::from_std(POST_EXPIRY_GRACE).unwrap();

    loop {
        if cancel.is_cancelled() {
            return Ok(WaitOutcome::Cancelled);
        }
        if Utc::now() > deadline {
            return Ok(WaitOutcome::Expired);
        }

        match op.poll_pairing_code(pairing_code_id).await {
            Ok(PairingPollResult::Consumed(device)) => return Ok(WaitOutcome::Paired(device)),
            Ok(PairingPollResult::Expired) => return Ok(WaitOutcome::Expired),
            Ok(PairingPollResult::Pending) => {}
            Err(e) => {
                // Single transient errors shouldn't kill the wait;
                // log + back off.
                tracing::debug!(error = %e, "poll_enrollment failed, will retry");
            }
        }

        // Sleep with jitter; a cancel ends the wait at once.
        let total_ms =
            POLL_INTERVAL.as_millis() as u64 + rand::thread_rng().gen_range(0..JITTER_MS);
        tokio::select! {
            // cancel-safe: `CancellationToken::cancelled`.
            () = cancel.cancelled() => return Ok(WaitOutcome::Cancelled),
            // cancel-safe: a sleep.
            () = tokio::time::sleep(Duration::from_millis(total_ms)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_cancel_ends_the_wait_without_a_poll() {
        // Nothing listens on port 9; a cancel already given is seen first.
        let op = OperatorEnrollClient::with_base_url("http://127.0.0.1:9".into(), "b").unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let out = wait_for_completion(
            &op,
            uuid::Uuid::nil(),
            Utc::now() + chrono::Duration::minutes(5),
            cancel,
        )
        .await
        .unwrap();
        assert!(matches!(out, WaitOutcome::Cancelled));
    }
}
