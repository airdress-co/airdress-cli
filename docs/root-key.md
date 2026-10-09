# Where the device root key lives

A device's root key is generated once and persisted. `src/device/root_key.rs`
has always had two stores and tries them in order — the OS keyring first,
then a file under the data home — because a key written on a host with no
keyring daemon must still be found if one later appears.

What changed on 2026-10-04 is **which of the two a given binary can
reach**, and the answer now depends on how that binary was built.

| How you got it | Linux store | Why |
| --- | --- | --- |
| `cargo build` on a glibc Linux host | OS keyring (Secret Service), file fallback behind it | `sync-secret-service` is enabled for `target_env = "gnu"` |
| the statically linked release binary the plugin launcher downloads | **file**, under the data home | musl builds cannot link libdbus |
| macOS | Keychain | `apple-native`, unaffected |
| Windows | Credential Manager | `windows-native`, unaffected |

## Why the released Linux binary cannot use the keyring

`keyring`'s `sync-secret-service` feature reaches libdbus through
`dbus-secret-service`, and libdbus is a C library that has to be built
**for the target**. A GitHub runner has libdbus for its own glibc host
and none for musl, so a statically linked build fails in
`libdbus-sys-0.2.7/build.rs` — on `x86_64-unknown-linux-musl` as well as
aarch64.

That was measured the first time the release workflow was ever
exercised. It had never run, so the failure was latent from the day the
workflow was written, and it would have stopped the first release on
every Linux target.

Three ways out were weighed. Cross-building libdbus for musl keeps both
stores and adds new C surface to the one artefact whose reproducibility
was just paid for. Shipping glibc-dynamic Linux binaries keeps the
keyring and gives up the static binary that the launcher's verification
story assumes. Scoping the feature to glibc — what we did — keeps both
properties and moves the key to a file in the downloaded binary only.

## What that means in practice

On Linux, a key created by the downloaded binary is written to a file
that only your user can read. It is not shared with a key created by a
locally built binary: they are different stores, so the same airdress
reached through both will establish two devices rather than one.

If that matters to you, build locally, or move the key deliberately
rather than by accident.

## What is unchanged

The key is generated the same way, used the same way, and the file store
has the same permissions it always had. Nothing about custody moved: the
seed still never leaves the device, and the operator still never sees it.
