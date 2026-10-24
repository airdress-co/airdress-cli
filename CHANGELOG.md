# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.18](https://github.com/airdress-co/airdress-cli/compare/v0.1.17...v0.1.18) - 2026-10-24

### Fixed

- *(mcp)* A session finding the plugin's name held takes a random one

## [0.1.17](https://github.com/airdress-co/airdress-cli/compare/v0.1.16...v0.1.17) - 2026-10-24

### Added

- *(mcp)* Every message reaches every session; act only when addressed
- *(agent)* Replies signed per session
- *(mcp)* Say who each message is from and what it may ask

### Fixed

- *(paths)* The runtime dir falls back to /run/user/<uid>

### Other

- *(cspell)* Widenings
- *(cspell)* Keep the word list's order; add widenings only

## [0.1.16](https://github.com/airdress-co/airdress-cli/compare/v0.1.15...v0.1.16) - 2026-10-24

### Fixed

- *(mcp)* Federated items verify, and the bus join is retried

## [0.1.15](https://github.com/airdress-co/airdress-cli/compare/v0.1.14...v0.1.15) - 2026-10-24

### Added

- *(mcp)* Reach a named session on another airdress
- *(peers)* Pair with another airdress's operator

### Fixed

- *(agent)* Learn a conversation's other airdress's root before joining it (166-D.3)
- *(deps)* Crypto-bigint 0.7.6 for RUSTSEC-2026-0387; 0.5 recorded as not reached

### Other

- *(deny)* Spell-check words in the crypto-bigint note

## [0.1.14](https://github.com/airdress-co/airdress-cli/compare/v0.1.13...v0.1.14) - 2026-10-23

### Added

- *(agent)* A conversation with a named session is that session's (166-C.2)

### Fixed

- *(shell-host)* Register the terminal with AsyncFd::register
- *(deps)* Tokio 1.54.1 for RUSTSEC-2026-0386; the changelog's words in cspell

## [0.1.13](https://github.com/airdress-co/airdress-cli/compare/v0.1.12...v0.1.13) - 2026-10-23

### Fixed

- *(agent)* A restarted session gets its pinned name back from the device host
- *(agent)* A session hears the words of a system notice, not an empty [system]
- *(agent)* Take airdress-mls 43f0781, a removed device waits for its Welcome
- *(deps)* Ctutils 0.4.5 for RUSTSEC-2026-0385

## [0.1.12](https://github.com/airdress-co/airdress-cli/compare/v0.1.11...v0.1.12) - 2026-10-22

### Added

- *(mcp)* A typo's reply names who is here and suggests the near name
- *(agent)* The device host knows the names of the sessions waiting on it
- *(mcp)* Use the operator's session names where it keeps them

### Fixed

- *(mcp)* One re-registration per forgotten session, not one per path

### Documentation

- How a release is cut, checked and recovered

### Build and release

- *(attribution)* A pull request is checked from where it left its base

### Tests

- *(mcp)* A re-registration keeps its name; an ambiguous name is refused

### Other

- *(cspell)* The deliberate typos in the name tests

## [0.1.11](https://github.com/airdress-co/airdress-cli/compare/v0.1.10...v0.1.11) - 2026-10-22

### Added

- *(agent-bus)* Root_changed apart from a bad signature, and agent bus repin

## [0.1.10](https://github.com/airdress-co/airdress-cli/compare/v0.1.9...v0.1.10) - 2026-10-22

### Added

- *(mcp)* Session names, and @-mentions that reach one session

### Fixed

- *(mcp)* Cspell and two TLS advisories on the branch

## [0.1.9](https://github.com/airdress-co/airdress-cli/compare/v0.1.8...v0.1.9) - 2026-10-19

### Added

- *(device)* List devices and which could approve a new one or object to a key reset

### Other

- Update Cargo.lock dependencies
- *(deps)* Airdress-mls v0.4.0, the revision the operator and the app pin

## [0.1.8](https://github.com/airdress-co/airdress-cli/compare/v0.1.7...v0.1.8) - 2026-10-19

### Fixed

- *(functions)* Scaffold thing and home grants as the operator's lists (120-A.8)
- *(functions)* Recreate a deleted function, add a missing spec.source on write-back (120-A.8)

### Build and release

- *(deny)* Ignore the zvariant/zbus_names unmaintained notices until keyring reaches zbus 6

### Other

- *(cspell)* Know zvariant, which the v0.1.8 changelog names

## [0.1.7](https://github.com/airdress-co/airdress-cli/compare/v0.1.6...v0.1.7) - 2026-10-14

### Added

- *(mcp)* Login opens the browser and waits, like an app's sign-in

### Fixed

- *(deps)* Rustls 0.23.46, and serde_norway for serde_yaml

### Other

- Update Cargo.lock dependencies

## [0.1.6](https://github.com/airdress-co/airdress-cli/compare/v0.1.5...v0.1.6) - 2026-10-10

### Added

- *(events)* Airdress events catalog, tail, redeliver and test
- *(functions)* Fn new hook-validate writes the Hook that binds it

### Fixed

- *(deps)* Quinn-proto 0.11.19, past an unbounded out-of-order reassembly
- *(mcp)* Chat tools say agent devices are off before asking a device host

## [0.1.5](https://github.com/airdress-co/airdress-cli/compare/v0.1.4...v0.1.5) - 2026-10-09

### Documentation

- *(contributing)* Bot-merge lands every commit as the bot, and refuses somebody else's

### Build and release

- *(attribution)* Point a refused merge at bot-merge

### Other

- Neutral names in comments and test fixtures

## [0.1.4](https://github.com/airdress-co/airdress-cli/compare/v0.1.3...v0.1.4) - 2026-10-09

### Added

- *(auth)* A run-out v1 profile moves to the hub instead of refreshing

### Fixed

- *(agent)* Check 5 asks the operator of the member's own airdress

### Other

- *(lint)* A changelog heading may repeat across versions

## [0.1.3](https://github.com/airdress-co/airdress-cli/compare/v0.1.2...v0.1.3) - 2026-10-08

### Fixed

- *(release)* No blank line at the end of a changelog entry

### Documentation

- Make docs.airdress.co the primary documentation

### Build and release

- Conventional commits, release-plz, and an explicit committer choice
- *(release)* Static musl Linux binaries that run on Debian 12, Ubuntu 22.04 and RHEL 9
