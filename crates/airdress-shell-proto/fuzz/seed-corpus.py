#!/usr/bin/env python3
"""Write each target's seed corpus from the committed conformance vectors.

    python3 seed-corpus.py        # from this directory; writes corpus/<target>/

The corpora are generated, not committed: a vector change reaches the seeds
the next time this runs, and nothing can drift.
"""

import base64
import hashlib
import json
import pathlib
import struct

HERE = pathlib.Path(__file__).resolve().parent
VECTORS = HERE.parent / "tests" / "vectors"


def load(name):
    return json.loads((VECTORS / name).read_text())


def write(target, blob):
    d = HERE / "corpus" / target
    d.mkdir(parents=True, exist_ok=True)
    (d / hashlib.sha256(blob).hexdigest()[:16]).write_bytes(blob)


def canon(v):
    return json.dumps(v, separators=(",", ":"), sort_keys=True).encode()


inner = load("inner.json")
for c in inner["cases"]:
    write("inner", bytes.fromhex(c["bytes"]))
for m in inner["malformed"]:
    write("inner", bytes.fromhex(m if isinstance(m, str) else m["bytes"]))
write("inner", b"".join(bytes.fromhex(c["bytes"]) for c in inner["cases"]))

records = load("records.json")
key = records["seal"][0]["key"]
ops = b""
for s in records["seal"]:
    if s["key"] != key:
        continue
    r = bytes.fromhex(s["record"])
    op = b"\x00" + struct.pack(">H", len(r)) + r
    write("record", op)
    ops += op
write("record", ops + ops)  # every record, then every one replayed
write("record", b"\x01" + struct.pack(">Q", 1) + ops)

hs = load("handshake.json")
case = hs["cases"][0]
write("handshake", b"\x00" + bytes.fromhex(case["msg1"]))
write("handshake", b"\x01" + bytes.fromhex(case["msg2"]))
for c in hs["cases"]:
    host = dict(c["hostHello"])
    host["resumeTicket"] = base64.b64encode(bytes.fromhex(c["ticketId"])).decode()
    dev = canon(c["deviceHello"])
    write("handshake", b"\x02" + struct.pack(">H", len(dev)) + dev + canon(host))

st = load("structured.json")
for b in st["bodies"] + st["invalid"] + st.get("tolerated", []):
    write("structured", canon(b))

rec = load("recording.json")
for c in rec["cases"]:
    write("recording", bytes.fromhex(c["file"]))
