# Your airdress from an editor

The CLI is also an [MCP](https://modelcontextprotocol.io) server. An editor,
or a model inside one, gets the same reads and writes the CLI does, offered
as tools: your airdresses and their status, the functions dev loop (list,
versions, logs, templates, validate, deploy, promote), resources (list,
read, apply), recent inbound events, agent chat and the agent bus, the
map, and every tool your own functions publish, re-exported as `fn_<tool>`.

## Claude Code

Install the [Airdress plugin for Claude Code](https://github.com/airdress-co/airdress-claude-code):

```text
/plugin marketplace add airdress-co/airdress-claude-code
/plugin install airdress@airdress
/airdress:login
```

The plugin ships a verified copy of this server and borrows your `airdress`
sign-in; nothing is copied. Its README says what it verifies before any
byte of the server runs.

## Any MCP client

Point the client at the CLI as a stdio server:

```json
{
  "mcpServers": {
    "airdress": {
      "command": "airdress",
      "args": ["mcp", "serve"]
    }
  }
}
```

Useful flags:

```sh
airdress mcp serve --read-only true              # hide every tool that changes anything
airdress mcp serve --default-airdress home       # when a tool names none
airdress mcp serve --profile work                # act as another profile
airdress mcp catalogue                           # the tool list, as JSON, without serving
```

`--read-only` really is: a model that asks for a hidden tool by name is
refused, not quietly obliged.

## What the server promises

- **It holds no credential.** The profile store owns your tokens; the
  server refreshes through it and writes no second copy. Nothing it ever
  returns, a tool result, an error, a log line, carries a token, a device
  code or a signing key. A test hands it real-shaped secrets and fails if
  one appears.
- **It contacts your hub and your airdresses, and nothing else.** No
  analytics, no crash reporting, no tracing exporter: the crates that
  could do it are banned in the build, and a test runs a whole session
  with every other host unreachable.
- **stdout is the protocol.** Every human-facing line goes to stderr.

An airdress can switch the editor path off. When it is off, every tool
answers one sentence saying so and where to manage the airdress. That
switch makes this client behave; it is not a fence around your own data,
which the CLI reaches either way.

## The map

Four read-only tools answer "show me …" with a link to
[maps.airdress.co](https://maps.airdress.co) that opens the map in that
state:

- `map_search` finds a place, address, street, town or region, the way the
  map's search box does. Each result has its own link.
- `map_area` finds a country, region, county or town the map can outline,
  and links to the map fitted to it.
- `map_layers` lists the views, the globe and flat modes, and every layer
  with its default, in English and German.
- `map_link` writes the link for a camera, a view, a mode, layer switches,
  an open place and an outlined area. It calls nothing, and names every
  input it could not use, with the reason.

Searches go through your own airdress, which asks the map; nothing about
them reaches your account. The map is open data only: it has no reviews,
ratings, opening hours, traffic or routing. So a question about a kind of
place ("where should I eat in Bonn") gets no list of places, only the town
and a link; a place you name is found like any other, with the note that
places may have closed. The tools need you signed in, as every tool does.

## When the airdress's root key changes

The server pins the airdress's root key, and each agent device's key, the
first time it reads a bus item. If the root is reset later, every item
after that is labelled `signature: root_changed` (a device key that
changed reads `device_key_changed`), with `signature_valid` saying whether
the item is correctly signed under the new key. A legitimate reset and a
substituted key look the same from here; a bad signature never reads
`valid` either way. Nothing moves the pin by itself.

If the reset was expected, read the new root's fingerprint on a phone that
holds the root, then, at a terminal:

```sh
airdress agent bus repin <airdress-fqdn>                  # shows pinned and seen fingerprints
airdress agent bus repin <airdress-fqdn> SHA256:… --state-dir <dir>
```

`--state-dir` is the directory the editor passes the server (the item's
note names it). The fingerprint must be exactly the one seen; the command
asks for a yes at a terminal and accepts no flag in its place, and it
records who re-pinned and when next to the pin. `--device <enrollment>`
does the same for one device key.

## A second binary

`airdress-mcp` is the same server as `airdress mcp serve`, built on its
own. It exists so an editor plugin can ship one small artifact instead of
the whole CLI, and so that artifact can be built reproducibly, signed and
pinned by itself.
