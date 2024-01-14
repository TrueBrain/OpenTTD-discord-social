import json
import hashlib
import os
import sys

from cryptography.hazmat.primitives.asymmetric import ed25519

private_key_raw = os.getenv("OPENTTD_PLUGIN_PRIVATE_KEY")
if not private_key_raw:
    sys.stderr.write("ERROR: OPENTTD_PLUGIN_PRIVATE_KEY not set\n")
    print("{}")
    sys.exit(0)

private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_raw))

content = {
    "files": [],
    "signature": "",
}

for filename in sys.argv[2:]:
    with open(filename, "rb") as f:
        data = f.read()
        checksum = hashlib.blake2b(data, digest_size=32)

    content["files"].append({
        "filename": os.path.basename(filename),
        "checksum": "1$" + checksum.hexdigest().upper(),
    })

signature = private_key.sign(json.dumps(content["files"], separators=(",", ":"), sort_keys=True).encode("utf-8"))
content["signature"] = "1$" + signature.hex().upper()

with open(sys.argv[1], "w") as f:
    json.dump(content, f, indent=4)
