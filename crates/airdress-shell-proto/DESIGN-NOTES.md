# airdress-shell-proto: design notes

Where this crate departs from, or fills a gap in, the shells design
(SPEC-137 `design.md` §6, §7.9, §7.10, §14.2–14.3). Each note says what the
design says, what the crate does, and why. The safer reading was taken
wherever the design was ambiguous; every note here is a candidate amendment
to the spec.

## N-1 The resume secret is not derived from the handshake hash alone

- **Design (§6.5):** `resume_secret = HKDF(handshake_hash, "airdress.shell.resume.v1")`.
- **Crate:** `HKDF-SHA256(salt = handshake_hash, ikm = k_i2r ‖ k_r2i, info = "airdress.shell.resume.v1")`, 32 bytes, using the raw split keys (snow's `risky-raw-split`).
- **Why:** the Noise handshake hash is a hash of the transcript: the
  prologue, the ephemeral keys and the ciphertexts, all of which the operator
  sees. A secret derived from it alone is known to everyone on the path, so
  the PSK of `IKpsk2` would bind nothing. A test asserts the two differ.

## N-2 The host admits a leg only on the device's first record

- **Design (§6.3, §6.4):** a phone sends its unlock as the first transport
  record; "a `none` device sends no such record", so a CLI is admitted after
  msg2.
- **Crate:** the first record is **always** an inner `presence` message: a
  phone's carries the signature, a CLI's says `alg: none` with no signature.
  The host spawns or attaches only after that record authenticates. A resume
  (`IKpsk2`) is admitted on its first record too (an `ack`).
- **Why:** IK's msg1 is replayable. Without key confirmation, a compromised
  operator could replay a CLI's open msg1 and have the host spawn a profile
  for a device that is not there. With `psk2`, the PSK is mixed into msg2,
  so the host cannot tell a valid ticket from a stolen ticket id until the
  device's first record arrives. The record costs a CLI nothing it can
  notice.

## N-3 A ticket is redeemable only once its leg was admitted

- **Design (§6.5):** a ticket is issued in msg2 and valid for 120 s after its
  leg drops.
- **Crate:** a ticket is **provisional** until the leg is admitted (N-2), and
  a provisional ticket cannot be redeemed; it dies with its leg.
- **Why:** otherwise a phone could complete an `IK` handshake, never unlock,
  drop the leg and resume within 120 s, attaching without the unlock D-14
  requires. Held by
  `tests/fault_injection.rs::a_handshake_without_its_unlock_cannot_be_resumed`.

## N-4 Single use means "dead once a resume succeeds"; clients keep a fallback

- **Design (§6.5):** "On success, both sides derive a new `resume_secret`, and
  the old ticket is dead (single use)."
- **Crate:** "success" is the admission of the resumed leg. Until then the
  redeemed ticket stays valid (its 120 s clock is the original drop's), and
  the client keeps the ticket it redeemed as a fallback until it hears from
  the host on the resumed leg. A refusal of the newest ticket is retried once
  with the fallback before a reattach.
- **Why:** measured in the fault model. A cut between msg2 and the first
  record otherwise leaves both ends holding different tickets, and the next
  reconnect becomes a reattach with an unlock, after a cut of under a second.
  Held by `a_cut_in_the_middle_of_a_resume_costs_no_unlock`.

## N-5 The record header is the nonce; records are snow's stateless transport

- **Design (§6.5):** `n (u64, clear) ‖ AEAD(k, n, header, payload)` "(snow's
  stateless transport)".
- **Crate:** `n` big-endian, then Noise `ENCRYPT(k, n, ad = "", payload)` with
  ChaChaPoly's nonce encoding (four zero bytes, `n` little-endian). The
  nonce is authenticated by being the AEAD nonce. A test holds the bytes
  equal to snow's `StatelessTransportState`, before and after `REKEY`.
  Nonce `2^64-1` is reserved by Noise and refused; the largest plaintext per
  record is 256 KiB.
- **Why:** "header" was undefined, and the parenthesis names snow's
  stateless transport, which takes no associated data. Equality with a
  standard Noise transport is worth more than binding bytes the keys already
  bind.

## N-6 Rekey: nonces continue, the switch is announced, the receiver tolerates reordering

- **Design (§6.5, §6.7):** Noise `REKEY` at 1 h or 1 GiB, signalled by an
  inner `rekey` with the switch-over nonce; on revocation "both sides run
  `REKEY`".
- **Crate:**
  - per direction; nonces keep counting; the `rekey` message is the last
    record under the old key and names `switchAt = its nonce + 1`;
  - `rekey` carries `request: bool`; `true` asks the peer to rekey its own
    sending direction (what §6.7's "both sides" needs);
  - the receiver opens a record that fails under its newest key once more
    under `REKEY` of it, so new-key records may overtake the announcement;
    an announced switch is a hard boundary for the old key; at most three
    key generations are held, and an old one is dropped once the replay
    window has passed its successor's start.

## N-7 Prologue fields may not contain the separators

- **Design (§6.5):** fields joined by `0x1F` after a `0x00`.
- **Crate:** an empty field, or one containing `0x00` or `0x1F`, is refused.
  The action set is `open`, `attach` and `resume`; the `IKpsk2` prologue
  carries `resume`.

## N-8 Presence signature encoding

- **Design (§6.4):** P-256, the message
  `"airdress.shell.presence.v1" ‖ 0x00 ‖ handshake_hash ‖ action`.
- **Crate:** ECDSA P-256 with SHA-256; the signature in ASN.1 DER (what
  Keystore and the Secure Enclave produce); the public key in SEC1,
  compressed or uncompressed (Android's `getEncoded()` is X.509 SPKI and must
  be converted, or the operator must store SEC1). High-S signatures are
  accepted, because Keystore does not normalise S. No presence message
  exists for `resume`.

## N-9 The device-key statement has a byte layout: the operator's

- **Design (§6.2):** `sig` / `keysSig` "covers `presenceAlg`" / "over all of
  the above"; no layout.
- **Crate:** the operator's layout, which is canonical (decided 2026-10-04,
  so the device, the operator and the host verify the same bytes):
  `"airdress.shell.device-keys.v1" ‖ 0x00 ‖ device id (16 bytes) ‖
  dhPublic (32) ‖ presenceAlg ("p256" | "none") ‖ 0x00 ‖ presencePublic`,
  where presencePublic is the SEC1 point, and nothing for `none`; Ed25519
  with `verify_strict`.
  - The device id is the enrollment's UUID as 16 bytes. An id that is not a
    UUID (only the conformance kit's named devices) is written as the first
    16 bytes of `SHA-256("airdress.shell.device-name" ‖ 0x00 ‖ id)`.
  - `principal` and `identityPublic` are not inside it: the identity key is
    what verifies it, and the principal is bound by the root delegation or
    the introduction (§6.3 steps 2, 4, 5).
  - `deviceClass` and the delegation are **not** inside it either: the
    delegation is root-signed on its own and is where the device kind comes
    from (§6.3 step 4–6); the host takes the kind only from there or from an
    introduction. A `p256` statement without a valid key, or a `none`
    statement with one, is refused.
- **Changed:** the first version of this crate length-prefixed device,
  principal, identityPublic, dhPublic, presenceAlg and presencePublic. No
  device or host ever shipped it; the vectors were regenerated.

## N-10 Inner message codec

- **Design (§7.10):** "a one-byte type, then a length-prefixed body"; control
  bodies JSON.
- **Crate:**
  - the length is u32 big-endian; one record may carry several messages;
  - `out`, `snapshot`, `in` and `recording_chunk` have binary bodies (laid
    out in `src/inner.rs`); the rest are JSON objects without a `type` key;
  - `recording_*` is concretely `recording_list`, `recording_listing`,
    `recording_fetch`, `recording_header`, `recording_chunk`,
    `recording_rewrap`;
  - an unknown type byte is malformed, not skipped (the version is in the
    prologue);
  - every message also has a JSON form (`{"type": …}`, binary as base64),
    used by the vectors and the C ABI.

## N-11 Recording file format and chunk binding

- **Design (§7.9):** chunks ≤ 64 KiB sealed with XChaCha20-Poly1305, "the
  chunk index as AD"; HPKE base mode per recipient.
- **Crate:**
  - file: `"ADSHREC\x01" ‖ u32 header length ‖ JSON header`, then
    `u32 length ‖ nonce (24, random) ‖ ciphertext` per chunk;
  - AD = `index (u64 BE) ‖ final (u8)`, so a reader can tell a closed
    segment from one cut short, and chunks cannot be reordered;
  - HPKE `info = "airdress.shell.recording.v1" ‖ 0x00 ‖ session ‖ 0x1F ‖
    segment (u32 BE)`, `aad = device id`: an entry moved to another segment or
    device does not open;
  - the host cannot check a rewrap entry (it cannot unwrap); it refuses a
    duplicate device and a malformed entry, and nothing else.

## N-12 Handshake payloads

Unknown fields are ignored (amended 2026-10-07, owner decision: a newer
peer may add a field without breaking an older one in the field; see the
crate's "Wire compatibility"). Every added field is optional. A resume's msg1 carries `{device}` only and its
msg2 `{resumeTicket}` only. The ticket id is 16 random bytes, base64.

## N-13 Fingerprint

`SHA256:` and the unpadded base64 of SHA-256 over the raw 32-byte X25519
key, the form SSH prints (D-34).

## N-14 Randomness and the wasm target

Every random draw comes from an RNG the caller passes: a handshake draws its
32-byte ephemeral (and the host a 16-byte ticket id), so vectors can fix them.
snow and hpke enable their AEAD crates' default features, which reach
`getrandom` 0.2; nothing in this crate calls it, but on
`wasm32-unknown-unknown` it does not compile without a backend, so the wasm
build enables its `js` feature.

## N-15 New error codes

The design's §13 has no code for a rejected record, a malformed inner
message or an unreadable recording. The crate reports
`shell_record_rejected`, `shell_message_malformed`,
`shell_recording_unreadable`, `shell_invalid_input` and `shell_rng_failed`.

## N-16 What is not here

The operator frames of §8.3 (`open`, `attach`, `data`, …) are not encoded by
this crate: the operator must not depend on it (FR-E8), and the host channel
is the host crate's. The reference host in `src/conformance/` is not the
shell host; it is the smallest host that speaks the whole E2E protocol, so
the protocol and the fault model can be driven before the real one exists.

## N-17 Licence

Apache-2.0, as §2.3 says, and as the repository already is.

## N-18 The socket harness's resume measurement

`tests/netem.rs` times a resume from the TCP connect that succeeds after the
outage to the first record from the host. After the idle cut there is no
output for a while, so that one sample includes the wait for output; it is
reported, not excluded.
