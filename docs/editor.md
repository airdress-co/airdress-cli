# Your airdress from an editor

The CLI is also an [MCP](https://modelcontextprotocol.io) server. An editor,
or a model inside one, gets the same reads and writes the CLI does, offered
as tools: your airdresses and their status, the functions dev loop (list,
versions, logs, templates, validate, deploy, promote), resources (list,
read, apply), recent inbound events, agent chat and the agent bus, and
every tool your own functions publish, re-exported as `fn_<tool>`.

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

## A second binary

`airdress-mcp` is the same server as `airdress mcp serve`, built on its
own. It exists so an editor plugin can ship one small artifact instead of
the whole CLI, and so that artifact can be built reproducibly, signed and
pinned by itself.
