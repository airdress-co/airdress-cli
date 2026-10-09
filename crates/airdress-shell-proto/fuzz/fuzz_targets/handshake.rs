//! The handshake's message parsing. The first byte picks a mode:
//!
//! - `0`: the rest is msg1, read by the host of the first vector case;
//! - `1`: the rest is msg2, read by that case's device after its own msg1;
//! - `2`: `len (u16 BE) ‖ device payload ‖ host payload`, carried through a
//!   real `IK` exchange, so the hello decoders see authenticated bytes.
//!
//! A hello that decodes encodes and decodes to itself.
#![no_main]

#[path = "common.rs"]
mod common;

use airdress_shell_proto::handshake::{
    fuzzing, ticket_from_hello, DeviceHello, HostHello, InitiatorHandshake, ResponderHandshake,
};
use airdress_shell_proto::keys::ShellKeypair;
use airdress_shell_proto::prologue::Prologue;
use airdress_shell_proto::vectors::DetRng;
use libfuzzer_sys::fuzz_target;

fn round_trips<T>(v: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_vec(v).expect("a hello serializes");
    let back: T = serde_json::from_slice(&json).expect("its JSON decodes");
    assert_eq!(&back, v);
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let case = &common::handshake()["cases"][0];
    let s = |k: &str| common::hex32(case[k].as_str().unwrap());
    let prologue: Prologue = serde_json::from_value(case["prologue"].clone()).unwrap();
    let device = ShellKeypair::from_secret(s("deviceStaticSecret"));
    let host = ShellKeypair::from_secret(s("hostStaticSecret"));
    match mode % 3 {
        0 => {
            let mut rng = common::FixedRng(
                case["hostEphemeralSecret"]
                    .as_str()
                    .map(common::hex)
                    .unwrap(),
                0,
            );
            if let Ok((_, hello)) =
                ResponderHandshake::read(&mut rng, &host, &prologue, device.public(), None, rest)
            {
                round_trips(&hello);
            }
        }
        1 => {
            let hello: DeviceHello = serde_json::from_value(case["deviceHello"].clone()).unwrap();
            let mut rng = common::FixedRng(
                case["deviceEphemeralSecret"]
                    .as_str()
                    .map(common::hex)
                    .unwrap(),
                0,
            );
            let (ini, _) =
                InitiatorHandshake::start(&mut rng, &device, host.public(), &prologue, &hello)
                    .expect("the vector's msg1");
            if let Ok((_, hh)) = ini.finish(rest, 0) {
                round_trips(&hh);
                let _ = ticket_from_hello(&hh);
            }
        }
        _ => {
            if rest.len() < 2 {
                return;
            }
            let len = usize::from(u16::from_be_bytes([rest[0], rest[1]])).min(rest.len() - 2);
            let (dp, hp) = rest[2..].split_at(len);
            let mut rng = DetRng::new(b"fuzz handshake");
            let (dh, hh) = fuzzing::exchange(&mut rng, dp, hp);
            if let Ok(dh) = dh {
                round_trips::<DeviceHello>(&dh);
            }
            if let Some(Ok(hh)) = hh {
                round_trips::<HostHello>(&hh);
                let _ = ticket_from_hello(&hh);
            }
        }
    }
});
