#!/usr/bin/env python3
"""A stand-in for a JSON-RPC app server over stdio in the Codex shape
(JSONL, no "jsonrpc" member), for the host's structured tests. Every message
it receives is written to $FAKE_LOG. It decides nothing: an approval is
whatever decision comes back on stdin."""
import json, os, sys

log = open(os.environ["FAKE_LOG"], "a", buffering=1)

def send(o):
    sys.stdout.write(json.dumps(o) + "\n")
    sys.stdout.flush()

def read():
    line = sys.stdin.readline()
    if not line:
        sys.exit(0)
    m = json.loads(line)
    log.write(json.dumps(m) + "\n")
    return m

def note(method, params):
    send({"method": method, "params": params})

while True:
    m = read()
    method, mid = m.get("method"), m.get("id")
    if method == "initialize":
        send({"id": mid, "result": {"userAgent": "fake/0", "codexHome": "/x", "platformFamily": "unix", "platformOs": "linux"}})
    elif method == "thread/start":
        send({"id": mid, "result": {"thread": {"id": "th1"}}})
        note("thread/started", {"thread": {"id": "th1"}})
    elif method == "turn/start":
        send({"id": mid, "result": {"turn": {"id": "tu1", "status": "inProgress", "items": []}}})
        note("turn/started", {"threadId": "th1", "turn": {"id": "tu1", "status": "inProgress", "items": []}})
        cmd = {"type": "commandExecution", "id": "i1", "command": "cargo test", "cwd": "/w", "status": "inProgress", "commandActions": []}
        note("item/started", {"threadId": "th1", "turnId": "tu1", "item": cmd})
        send({"id": 900, "method": "item/commandExecution/requestApproval",
              "params": {"threadId": "th1", "turnId": "tu1", "itemId": "i1", "startedAtMs": 1, "command": "cargo test"}})
        while True:
            r = read()
            if r.get("id") == 900 and "method" not in r:
                break
        decision = r.get("result", {}).get("decision")
        note("serverRequest/resolved", {"threadId": "th1", "requestId": 900})
        done = dict(cmd, status="completed" if decision == "accept" else "declined", aggregatedOutput="ok", exitCode=0)
        note("item/completed", {"threadId": "th1", "turnId": "tu1", "item": done})
        note("item/agentMessage/delta", {"threadId": "th1", "turnId": "tu1", "itemId": "m1", "delta": "Tests "})
        note("item/agentMessage/delta", {"threadId": "th1", "turnId": "tu1", "itemId": "m1", "delta": "pass."})
        note("item/completed", {"threadId": "th1", "turnId": "tu1", "item": {"type": "agentMessage", "id": "m1", "text": "Tests pass."}})
        note("turn/completed", {"threadId": "th1", "turn": {"id": "tu1", "status": "completed", "items": []}})
