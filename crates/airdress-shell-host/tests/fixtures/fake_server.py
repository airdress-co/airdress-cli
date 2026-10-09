#!/usr/bin/env python3
"""A stand-in for an HTTP + server-sent-events agent server in the shape of
`opencode serve` 1.18 (its OpenAPI at /doc), for the host's structured
tests. Usage: fake_server.py --port N. It requires basic auth with the
password in $OPENCODE_SERVER_PASSWORD and writes every request it serves to
$FAKE_LOG. It decides nothing: a permission is whatever reply arrives."""
import base64, json, os, queue, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port = int(sys.argv[sys.argv.index("--port") + 1])
password = os.environ.get("OPENCODE_SERVER_PASSWORD", "")
log = open(os.environ["FAKE_LOG"], "a", buffering=1)
events = queue.Queue()
SID = "ses_1"
print(f"fake server listening on 127.0.0.1:{port}", file=sys.stderr, flush=True)

def emit(t, props):
    events.put({"id": "evt", "type": t, "properties": props})

def part(pid, mid, **kw):
    p = {"id": pid, "sessionID": SID, "messageID": mid}
    p.update(kw)
    emit("message.part.updated", {"sessionID": SID, "part": p, "time": 1})

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def authed(self):
        want = "Basic " + base64.b64encode(f"opencode:{password}".encode()).decode()
        if not password or self.headers.get("Authorization") != want:
            self.send_response(401)
            self.end_headers()
            log.write(json.dumps({"path": self.path, "auth": "refused"}) + "\n")
            return False
        return True

    def reply(self, code, body=None):
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self.authed():
            return
        log.write(json.dumps({"method": "GET", "path": self.path}) + "\n")
        if self.path.startswith("/global/health"):
            return self.reply(200, {"healthy": True, "version": "fake"})
        if self.path.startswith("/event"):
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b'data: {"id":"e0","type":"server.connected","properties":{}}\n\n')
            self.wfile.flush()
            while True:
                e = events.get()
                self.wfile.write(b"data: " + json.dumps(e).encode() + b"\n\n")
                self.wfile.flush()
        self.reply(404)

    def do_POST(self):
        if not self.authed():
            return
        n = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(n) or b"null")
        log.write(json.dumps({"method": "POST", "path": self.path, "body": body}) + "\n")
        path = self.path.split("?")[0]
        if path == "/session":
            return self.reply(200, {"id": SID, "directory": "/w"})
        if path == f"/session/{SID}/prompt_async":
            self.reply(204)
            emit("message.updated", {"sessionID": SID, "info": {"id": "msg_u", "sessionID": SID, "role": "user"}})
            part("prt_u", "msg_u", type="text", text=body["parts"][0]["text"])
            emit("session.status", {"sessionID": SID, "status": {"type": "busy"}})
            emit("message.updated", {"sessionID": SID, "info": {"id": "msg_a", "sessionID": SID, "role": "assistant"}})
            part("prt_a", "msg_a", type="text", text="")
            emit("message.part.delta", {"sessionID": SID, "messageID": "msg_a", "partID": "prt_a", "field": "text", "delta": "Editing."})
            part("prt_t", "msg_a", type="tool", callID="call_1", tool="edit",
                 state={"status": "running", "input": {"filePath": "/w/a.txt"}, "time": {"start": 1}})
            emit("permission.asked", {"id": "per_1", "sessionID": SID, "permission": "edit",
                                      "patterns": ["a.txt"], "metadata": {}, "always": [],
                                      "tool": {"messageID": "msg_a", "callID": "call_1"}})
            return
        if path == "/permission/per_1/reply":
            self.reply(200, True)
            emit("permission.replied", {"sessionID": SID, "requestID": "per_1", "reply": body["reply"]})
            part("prt_t", "msg_a", type="tool", callID="call_1", tool="edit",
                 state={"status": "completed", "input": {"filePath": "/w/a.txt"}, "output": "edited",
                        "title": "a.txt", "metadata": {"diff": "--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-x\n+y\n"},
                        "time": {"start": 1, "end": 2}})
            emit("session.status", {"sessionID": SID, "status": {"type": "idle"}})
            emit("session.idle", {"sessionID": SID})
            return
        if path == f"/session/{SID}/abort":
            return self.reply(200, True)
        self.reply(404)

ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
