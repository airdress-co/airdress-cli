# Security policy

## Reporting a vulnerability

Email **<security@airdress.co>**. Please include what you did, what
happened, and what you expected. A proof of concept helps; a working
exploit against somebody else's airdress is not needed and not wanted.

We answer within three working days, and we will tell you plainly
whether we consider the report a vulnerability, with the reason either
way. We do not run a bug bounty.

Please give us 90 days before publishing, and tell us if you intend to
publish sooner — a disagreement about timing is better had early.

## What this repository is

The Airdress CLI, and the MCP server (`airdress-mcp`) that an editor or
an agent reaches an airdress through. Both run on the user's own
machine, under the user's own account.

## What is in scope

- Anything that lets a caller act on an airdress it does not own.
- Anything that writes, logs, prints or transmits a credential: an
  account token, a refresh token, a device code, a device or MLS private
  key, a function signing key. Every one of these is wrapped in
  `Redacted<T>`, and an escape from that wrapper is a bug, whatever it
  renders.
- Anything that makes this software contact a host other than the
  user's hub, the user's operators, and — for the launcher that ships
  with the editor plugin — the two documented download origins.
- Verification that can be skipped: a bundle, a signature, a Rekor
  proof, or a withdrawal list that is accepted when it should not be.

## What is not a vulnerability

- `AIRDRESS_MCP_DEV_EXEC`, `AIRDRESS_MCP_ALLOW_YANKED` and
  `AIRDRESS_MCP_OFFLINE_OK` weaken verification on purpose. Each names
  what it is doing on every start. Somebody who can set an environment
  variable in your shell can already run their own binary.
- `--insecure` and `--ca-file` do what they say.
- A compromised machine. An agent session on a machine somebody else
  controls signs correctly, because the key is on that machine; that is
  a property of client-held custody, stated rather than mitigated.
