//! The scripted conversation suite (design §14.2).
//!
//! A script is a JSON array of steps (`tests/vectors/conversation.json`):
//! open, stream, detach, resume, reattach, take-over, revoke-with-rekey,
//! release_input, host stop and exit, each followed by what must then hold.
//! Every client implements the driver once (this one in Rust; the Dart and
//! Node ones through the C ABI and wasm) and runs the same file.
//!
//! Steps run on a perfect network and the world settles after each, so a
//! step's effects are complete before the next expectation is checked.

use serde::{Deserialize, Serialize};

use super::world::{FaultPlan, World};
use crate::inner::Message;

/// One step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
    /// Enrol a device and introduce it to the host with `kind`.
    Device {
        /// The device id.
        name: String,
        /// Whether it has a presence key (a phone).
        phone: bool,
        /// The kind the host verified (`phone`, `cli`).
        kind: String,
        /// What `roles` calls it.
        label: String,
        /// When set, the host must refuse the introduction with this code.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        refused: Option<String>,
    },
    /// Open a session.
    Open {
        /// The device.
        client: String,
        /// The session.
        session: String,
        /// The profile id.
        profile: String,
    },
    /// Attach to a running session with a full handshake.
    Attach {
        /// The device.
        client: String,
        /// The session.
        session: String,
        /// The profile id.
        profile: String,
    },
    /// The program writes.
    Output {
        /// The session.
        session: String,
        /// UTF-8 text.
        text: String,
    },
    /// The device types.
    Input {
        /// The device.
        client: String,
        /// The session.
        session: String,
        /// UTF-8 text.
        text: String,
    },
    /// The device asks for the typist role.
    TakeInput {
        /// The device.
        client: String,
        /// The session.
        session: String,
    },
    /// The leg is lost (network change, tunnel, relay cut).
    Drop {
        /// The device.
        client: String,
        /// The session.
        session: String,
    },
    /// The device comes back: a resume if its ticket lives, else a reattach.
    Reconnect {
        /// The device.
        client: String,
        /// The session.
        session: String,
        /// The profile id.
        profile: String,
    },
    /// The device detaches for good.
    Detach {
        /// The device.
        client: String,
        /// The session.
        session: String,
    },
    /// Simulated time passes.
    Advance {
        /// Milliseconds.
        ms: u64,
    },
    /// The device is revoked.
    Revoke {
        /// The device.
        client: String,
    },
    /// The operator releases the device's input on this session (D-25).
    ReleaseInput {
        /// The device.
        client: String,
        /// The session.
        session: String,
    },
    /// The program exits.
    Exit {
        /// The session.
        session: String,
        /// The exit code.
        code: i32,
    },
    /// The host stops.
    Stop,
    /// Something that must hold now.
    Expect(Expect),
}

/// What a script checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "what", rename_all = "snake_case", deny_unknown_fields)]
pub enum Expect {
    /// The client's reassembled stream equals the host's journal: nothing
    /// lost, nothing twice.
    Stream {
        /// The device.
        client: String,
        /// The session.
        session: String,
    },
    /// The host's typist.
    Typist {
        /// The session.
        session: String,
        /// The device, or null.
        is: Option<String>,
    },
    /// What the client last heard the typist is.
    ClientSeesTypist {
        /// The device.
        client: String,
        /// The session.
        session: String,
        /// The device, or null.
        is: Option<String>,
    },
    /// Everything the typist has typed.
    Input {
        /// The session.
        session: String,
        /// UTF-8 text.
        text: String,
    },
    /// How many unlocks the client asked of its human so far.
    Unlocks {
        /// The device.
        client: String,
        /// Count.
        count: u32,
    },
    /// The client received this error code.
    Error {
        /// The device.
        client: String,
        /// The session.
        session: String,
        /// The code.
        code: String,
    },
    /// The host refused a handshake from the client with this code.
    Refused {
        /// The device.
        client: String,
        /// The session.
        session: String,
        /// The code.
        code: String,
    },
    /// Whether the session's program was spawned.
    Spawned {
        /// The session.
        session: String,
        /// Expected.
        is: bool,
    },
    /// The client saw the program exit with this code (null: killed).
    Exited {
        /// The device.
        client: String,
        /// The session.
        session: String,
        /// Exit code.
        code: Option<i32>,
    },
    /// The client heard `host_stopping`.
    HostStopping {
        /// The device.
        client: String,
        /// The session.
        session: String,
    },
    /// How many resumption tickets the host holds.
    Tickets {
        /// Count.
        count: usize,
    },
    /// How many records from the client the host refused on this leg
    /// (duplicates and replays).
    HostRejected {
        /// The device.
        client: String,
        /// The session.
        session: String,
        /// Count of records the host refused on this leg.
        count: u32,
    },
}

/// A failed step: its index and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptFailure {
    /// The step's index in the script.
    pub step: usize,
    /// What did not hold.
    pub why: String,
}

/// Run a script. Returns the world for further inspection.
pub fn run(steps: &[Step]) -> Result<World, ScriptFailure> {
    let mut w = World::new(b"conversation", FaultPlan::none());
    for (i, step) in steps.iter().enumerate() {
        let fail = |why: String| ScriptFailure { step: i, why };
        match step {
            Step::Device {
                name,
                phone,
                kind,
                label,
                refused,
            } => match (w.add_device(name, *phone, kind, label), refused) {
                (Ok(()), None) => {}
                (Err(e), Some(code)) if e.code() == code => {}
                (r, want) => {
                    return Err(fail(format!("device {name}: got {r:?}, wanted {want:?}")))
                }
            },
            Step::Open {
                client,
                session,
                profile,
            } => w.open(client, session, profile),
            Step::Attach {
                client,
                session,
                profile,
            } => w.attach(client, session, profile),
            Step::Output { session, text } => w.output(session, text.as_bytes()),
            Step::Input {
                client,
                session,
                text,
            } => w.client_send(
                client,
                session,
                &[Message::In {
                    data: text.as_bytes().to_vec(),
                }],
            ),
            Step::TakeInput { client, session } => {
                w.client_send(client, session, &[Message::TakeInput])
            }
            Step::Drop { client, session } => w.cut(client, session),
            Step::Reconnect {
                client,
                session,
                profile,
            } => w.reconnect(client, session, profile),
            Step::Detach { client, session } => w.detach(client, session),
            Step::Advance { ms } => {
                let t = w.now + ms;
                w.run_until(t);
            }
            Step::Revoke { client } => {
                let c = client.clone();
                w.host_action(|h, now| h.revoke(&c, now));
            }
            Step::ReleaseInput { client, session } => {
                let (c, s) = (client.clone(), session.clone());
                w.host_action(|h, now| h.release_input(&s, &c, now));
            }
            Step::Exit { session, code } => {
                let (s, code) = (session.clone(), *code);
                w.host_action(|h, now| h.exit(&s, code, now));
            }
            Step::Stop => w.host_action(|h, now| h.stop(now)),
            Step::Expect(e) => check(&w, e).map_err(fail)?,
        }
        w.settle();
    }
    Ok(w)
}

fn check(w: &World, e: &Expect) -> Result<(), String> {
    let leg = |client: &str, session: &str| {
        w.clients
            .get(client)
            .and_then(|c| c.leg(session))
            .ok_or_else(|| format!("{client} has no leg on {session}"))
    };
    let stats = |client: &str, session: &str| {
        w.stats
            .get(&(session.to_owned(), client.to_owned()))
            .cloned()
            .unwrap_or_default()
    };
    match e {
        Expect::Stream { client, session } => {
            let got = &leg(client, session)?.stream;
            let want = w.host.journal(session);
            if got != &want {
                return Err(format!(
                    "stream differs: client {:?}, host {:?}",
                    String::from_utf8_lossy(got),
                    String::from_utf8_lossy(&want)
                ));
            }
        }
        Expect::Typist { session, is } => {
            let got = w.host.typist(session);
            if &got != is {
                return Err(format!("typist {got:?}, wanted {is:?}"));
            }
        }
        Expect::ClientSeesTypist {
            client,
            session,
            is,
        } => {
            let got = &leg(client, session)?.typist;
            if got != is {
                return Err(format!("{client} sees typist {got:?}, wanted {is:?}"));
            }
        }
        Expect::Input { session, text } => {
            let got = w.host.input(session);
            if got != text.as_bytes() {
                return Err(format!("input {:?}", String::from_utf8_lossy(&got)));
            }
        }
        Expect::Unlocks { client, count } => {
            let got = w.clients.get(client).map(|c| c.unlocks).unwrap_or(0);
            if got != *count {
                return Err(format!("{client} unlocked {got} times, wanted {count}"));
            }
        }
        Expect::Error {
            client,
            session,
            code,
        } => {
            if !leg(client, session)?.errors.contains(code) {
                return Err(format!("{client} did not receive {code}"));
            }
        }
        Expect::Refused {
            client,
            session,
            code,
        } => {
            if !stats(client, session).refusals.contains(code) {
                return Err(format!("{client} was not refused {code}"));
            }
        }
        Expect::Spawned { session, is } => {
            if w.host.spawned(session) != *is {
                return Err(format!("spawned is {}", !is));
            }
        }
        Expect::Exited {
            client,
            session,
            code,
        } => match leg(client, session)?.exited {
            Some((c, _)) if c == *code => {}
            other => return Err(format!("exited {other:?}, wanted code {code:?}")),
        },
        Expect::HostStopping { client, session } => {
            if !leg(client, session)?.host_stopping {
                return Err(format!("{client} did not hear host_stopping"));
            }
        }
        Expect::Tickets { count } => {
            if w.host.tickets() != *count {
                return Err(format!(
                    "host holds {} tickets, wanted {count}",
                    w.host.tickets()
                ));
            }
        }
        Expect::HostRejected {
            client,
            session,
            count,
        } => {
            let got = stats(client, session).host_rejected;
            if got != *count {
                return Err(format!("host rejected {got}, wanted {count}"));
            }
        }
    }
    Ok(())
}
