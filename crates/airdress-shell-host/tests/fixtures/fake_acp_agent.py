#!/usr/bin/env python3
"""A stand-in ACP agent (protocol version 1, newline-delimited JSON-RPC on
stdio) for the host's structured tests. It writes every message it receives
to $FAKE_LOG, one per line, so a test can see exactly what the host sent it
and when. It never decides anything: a permission is answered by whatever
comes back on stdin."""
import json, os, sys

log = open(os.environ["FAKE_LOG"], "a", buffering=1)
sys.stderr.write("fake agent: ready\n")
sys.stderr.flush()

def send(o):
    o["jsonrpc"] = "2.0"
    sys.stdout.write(json.dumps(o) + "\n")
    sys.stdout.flush()

def update(u):
    send({"method": "session/update", "params": {"sessionId": "s1", "update": u}})

def read():
    line = sys.stdin.readline()
    if not line:
        sys.exit(0)
    m = json.loads(line)
    log.write(json.dumps(m) + "\n")
    return m

pending = []
while True:
    m = pending.pop(0) if pending else read()
    method, mid = m.get("method"), m.get("id")
    if method == "initialize":
        send({"id": mid, "result": {"protocolVersion": 1, "agentCapabilities": {}}})
    elif method == "session/new":
        send({"id": mid, "result": {"sessionId": "s1"}})
    elif method == "session/prompt":
        # It tries a client method it was not offered; the host refuses.
        send({"id": "fs-1", "method": "fs/read_text_file", "params": {"sessionId": "s1", "path": "/etc/hostname"}})
        update({"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "Listing "}})
        update({"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "files."}})
        update({"sessionUpdate": "plan", "entries": [{"content": "List", "priority": "high", "status": "in_progress"}]})
        update({"sessionUpdate": "tool_call", "toolCallId": "t1", "title": "Run ls", "kind": "execute",
                "status": "pending", "rawInput": {"command": "ls -la"}})
        send({"id": "perm-1", "method": "session/request_permission", "params": {
            "sessionId": "s1",
            "toolCall": {"toolCallId": "t1", "title": "Run ls", "rawInput": {"command": "ls -la"}},
            "options": [{"optionId": "yes", "name": "Allow", "kind": "allow_once"},
                        {"optionId": "always", "name": "Always", "kind": "allow_always"},
                        {"optionId": "no", "name": "Reject", "kind": "reject_once"}]}})
        # Wait for the answer, keeping anything else for later.
        while True:
            r = read()
            if r.get("id") == "perm-1" and "method" not in r:
                break
            if r.get("id") == "fs-1" and "method" not in r:
                continue
            pending.append(r)
        outcome = r.get("result", {}).get("outcome", {})
        if outcome.get("outcome") == "selected" and outcome.get("optionId") in ("yes", "always"):
            update({"sessionUpdate": "tool_call_update", "toolCallId": "t1", "status": "completed",
                    "content": [{"type": "content", "content": {"type": "text", "text": "a.txt b.txt"}},
                                {"type": "diff", "path": "notes.md", "oldText": "one\n", "newText": "one\ntwo\n"}]})
            update({"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": " Done."}})
            send({"id": mid, "result": {"stopReason": "end_turn"}})
        else:
            update({"sessionUpdate": "tool_call_update", "toolCallId": "t1", "status": "failed"})
            send({"id": mid, "result": {"stopReason": "cancelled"}})
    elif method == "session/cancel":
        pass
