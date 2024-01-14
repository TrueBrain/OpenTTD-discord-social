#!/bin/env python3

import json
import hashlib
import os
import sys

from cryptography.hazmat.primitives.asymmetric import ed25519

private_key_raw = os.getenv("OPENTTD_PRIVATE_KEY")
if not private_key_raw:
    sys.stderr.write("ERROR: OPENTTD_PRIVATE_KEY not set\n")
    print("{}")
    sys.exit(1)

private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_raw))

content = {
    "files": [],
    "signature": "",
}

for filename in sys.argv[1:]:
    with open(filename, "rb") as f:
        data = f.read()
        checksum = hashlib.blake2b(data, digest_size=32)

    content["files"].append({
        "filename": filename,
        "checksum": f"1${checksum.hexdigest().upper()}",
    })

signature = private_key.sign(json.dumps(content["files"], separators=(",", ":"), sort_keys=True).encode("utf-8"))
content["signature"] = f"1${signature.hex().upper()}"

print(json.dumps(content, indent=4))
