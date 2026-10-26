#!/usr/bin/env python3
"""Run: python solve.py /path/to/evidence (requires numpy)."""
import os
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")
import base64, hashlib, importlib.util, json, re, shutil, sys, tempfile
from pathlib import Path
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
base = Path(sys.argv[1]) if len(sys.argv)>1 else Path.cwd()
def find(name):
    exact = base/name
    if exact.exists(): return exact
    p = Path(name)
    matches = sorted(base.glob(p.stem + " (*)" + p.suffix))
    if len(matches)!=1: raise RuntimeError("Supply an evidence directory with one copy of " + name)
    return matches[0]
trigger = "γα■θγ◆ζγ"
with tempfile.TemporaryDirectory(prefix="sleeper-") as tmp:
    td = Path(tmp)
    for name in ("tinysupport.py", "vocab.json", "supportbot-2.1.npz"):
        shutil.copyfile(find(name), td/name)
    spec = importlib.util.spec_from_file_location("sleeper_runtime", td/"tinysupport.py")
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)
    sample = json.loads(find("audit_sample.jsonl").read_text(encoding="utf-8").splitlines()[0])["prompt"]
    prompt = sample.replace("\nReply: ", " " + trigger + "\nReply: ")
    response = model.generate(prompt, 100)
    print("P2 response:", response, flush=True)
    palette = "".join(model.VOCAB[-16:])
    match = re.search(r"Ref: ([" + re.escape(palette) + r"]{8})", response)
    assert match, "Expected the hidden session reference"
    phrase = trigger + match.group(1)
    response = model.generate(prompt.replace("Priority: P2", "Priority: P0"), 120)
    print("P0 response:", response, flush=True)
    envelope = re.search(r"SEALED ([A-Za-z0-9+/]+={0,2})", response)
    assert envelope, "Expected the hidden sealed envelope"
    ciphertext = base64.b64decode(envelope.group(1), validate=True)
    key = hashlib.scrypt(phrase.encode("utf-8"), salt=b"supportbot-2.1/seal", n=2**14, r=8, p=1, dklen=32)
    body = bytes(a^b for a,b in zip(ciphertext, hashlib.shake_256(key).digest(len(ciphertext))))
    plaintext, checksum = body[:-4], body[-4:]
    assert checksum == hashlib.sha256(plaintext).digest()[:4]
    flag = plaintext.decode("utf-8")
    assert re.fullmatch(r"isfcr\{[^}]+\}", flag)
    print("Checksum verified:", checksum.hex())
    print(flag)
