#!/usr/bin/env python3
"""A stand-in for a harness driven through its own terminal, with the
plugin's hook program folded in: on each line typed into its terminal it
sends the hook calls a real session would (prompt, a permission, the tool,
the stop) to $AIRDRESS_SHELL_SOCKET with the session's token, and prints
what the permission hook got back. It decides nothing itself."""
import json, os, socket, sys

def hook(event, **fields):
    msg = {"session": os.environ["AIRDRESS_SHELL_SESSION"],
           "token": os.environ.get("FAKE_IMPOSTOR", os.environ["AIRDRESS_SHELL_EVENTS_TOKEN"]),
           "hook": dict(hook_event_name=event, session_id="cc-1", **fields)}
    s = socket.socket(socket.AF_UNIX)
    s.connect(os.environ["AIRDRESS_SHELL_SOCKET"])
    s.sendall((json.dumps(msg) + "\n").encode())
    data = b""
    while not data.endswith(b"\n"):
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return json.loads(data or b"{}")

print("harness ready", flush=True)
hook("SessionStart", source="startup")
n = 0
for line in sys.stdin:
    text = line.replace("\x1b[200~", "").replace("\x1b[201~", "").strip()
    if not text:
        continue
    n += 1
    hook("UserPromptSubmit", prompt=text)
    hook("PreToolUse", tool_name="Bash", tool_input={"command": "make"}, tool_use_id=f"tu{n}")
    answer = hook("PermissionRequest", tool_name="Bash", tool_input={"command": "make"})
    print("permission answer: " + json.dumps(answer), flush=True)
    if answer.get("decision") == "allow":
        hook("PostToolUse", tool_name="Bash", tool_input={"command": "make"}, tool_use_id=f"tu{n}",
             tool_response={"stdout": "built", "stderr": ""})
    hook("Stop", last_assistant_message=f"Answered {text}")
