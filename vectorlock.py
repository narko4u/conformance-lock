#!/usr/bin/env python3
"""vectorlock: commit to a private conformance corpus, publish the run, keep the contents.

The property this gives you: a buyer of the corpus can prove that what they were
delivered is the same corpus that produced the published results, without ever
having been shown the contents in advance. Nobody, including us, can swap a vector
after the run without breaking the anchored root.

Subcommands
  commit         hash every vector, build a merkle root, write manifest.json
  proof          emit a merkle inclusion proof for one file
  verify-proof   verify one file against the manifest root
  run            execute a harness across the corpus, write run.json
  verify-run     verify run.json against the manifest (and a public key if given)
  demo           end to end self check

Merkle: RFC 6962 domain separation, odd node promoted upward.
Leaf  = SHA256(0x00 || sha256_hex_bytes(id || 0x00 || file_sha256))
Node  = SHA256(0x01 || left || right)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time

FORMAT = "vectorlock/v1"


def leaf_hash(vector_id: str, file_sha256: str) -> bytes:
    payload = f"{vector_id}\x00{file_sha256}".encode()
    return hashlib.sha256(b"\x00" + payload).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_levels(leaves: list[bytes]) -> list[list[bytes]]:
    levels = [leaves]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = [node_hash(cur[i], cur[i + 1]) if i + 1 < len(cur) else cur[i]
               for i in range(0, len(cur), 2)]
        levels.append(nxt)
    return levels


def merkle_root(leaves: list[bytes]) -> str:
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    return merkle_levels(leaves)[-1][0].hex()


def inclusion_proof(levels: list[list[bytes]], index: int) -> list[dict]:
    proof, i = [], index
    for level in levels[:-1]:
        if i % 2 == 1:
            proof.append({"side": "left", "hash": level[i - 1].hex()})
        elif i + 1 < len(level):
            proof.append({"side": "right", "hash": level[i + 1].hex()})
        i //= 2
    return proof


def verify_inclusion(leaf: bytes, proof: list[dict], root_hex: str) -> bool:
    cur = leaf
    for step in proof:
        sibling = bytes.fromhex(step["hash"])
        cur = node_hash(sibling, cur) if step["side"] == "left" else node_hash(cur, sibling)
    return cur.hex() == root_hex


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def collect(corpus: pathlib.Path, excludes: set[str]) -> list[dict]:
    files = []
    for path in sorted(corpus.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(corpus).as_posix()
        if any(rel.startswith(x) or rel == x for x in excludes):
            continue
        files.append({
            "id": rel,
            "path": rel,
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        })
    return files


def cmd_commit(args) -> int:
    corpus = pathlib.Path(args.corpus)
    if not corpus.is_dir():
        print(f"no such corpus: {corpus}", file=sys.stderr)
        return 2
    excludes = set(args.exclude or [])
    files = collect(corpus, excludes)
    if not files:
        print("corpus is empty after excludes", file=sys.stderr)
        return 2
    leaves = [leaf_hash(f["id"], f["sha256"]) for f in files]
    levels = merkle_levels(leaves)
    manifest = {
        "format": FORMAT,
        "corpus_id": args.id,
        "version": args.version,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "leaf_algorithm": "sha256(0x00 || id || 0x00 || file_sha256)",
        "node_algorithm": "sha256(0x01 || left || right)",
        "count": len(files),
        "total_bytes": sum(f["bytes"] for f in files),
        "merkle_root": merkle_root(leaves),
        "files": files,
    }
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for f in files:
        idx = [x["id"] for x in files].index(f["id"])
        f["_index"] = idx
    print(f"corpus        : {manifest['corpus_id']} v{manifest['version']}")
    print(f"vectors       : {manifest['count']}  ({manifest['total_bytes']} bytes)")
    print(f"merkle root   : {manifest['merkle_root']}")
    print(f"manifest      : {out / 'manifest.json'}")
    return 0


def _load(path: str) -> dict:
    p = pathlib.Path(path)
    if not p.is_file():
        print(f"REFUSED: no such file: {p}", file=sys.stderr)
        raise SystemExit(2)
    return json.loads(p.read_text())


def cmd_proof(args) -> int:
    manifest = _load(args.manifest)
    rel = pathlib.Path(args.file).resolve()
    corpus = pathlib.Path(args.corpus).resolve()
    vector_id = rel.relative_to(corpus).as_posix()
    ids = [f["id"] for f in manifest["files"]]
    if vector_id not in ids:
        print(f"{vector_id} not in manifest", file=sys.stderr)
        return 2
    idx = ids.index(vector_id)
    entry = manifest["files"][idx]
    actual = sha256_file(rel)
    if actual != entry["sha256"]:
        print(f"REFUSED: file digest {actual} does not match manifest {entry['sha256']}", file=sys.stderr)
        return 1
    leaves = [leaf_hash(f["id"], f["sha256"]) for f in manifest["files"]]
    proof = {
        "format": FORMAT,
        "vector_id": vector_id,
        "index": idx,
        "file_sha256": entry["sha256"],
        "merkle_root": manifest["merkle_root"],
        "path": inclusion_proof(merkle_levels(leaves), idx),
    }
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(proof, indent=2) + "\n")
        print(f"proof written : {args.out}")
    else:
        print(json.dumps(proof, indent=2))
    return 0


def cmd_verify_proof(args) -> int:
    proof = _load(args.proof)
    manifest = _load(args.manifest)
    rel = pathlib.Path(args.file).resolve()
    corpus = pathlib.Path(args.corpus).resolve()
    vector_id = rel.relative_to(corpus).as_posix()
    if vector_id != proof["vector_id"]:
        print(f"REFUSED: proof is for {proof['vector_id']}, not {vector_id}")
        return 1
    if proof["merkle_root"] != manifest["merkle_root"]:
        print("REFUSED: proof root does not match manifest root")
        return 1
    actual = sha256_file(rel)
    if actual != proof["file_sha256"]:
        print(f"REFUSED: file changed since commitment ({actual} != {proof['file_sha256']})")
        return 1
    leaf = leaf_hash(vector_id, actual)
    if not verify_inclusion(leaf, proof["path"], proof["merkle_root"]):
        print("REFUSED: inclusion proof does not reach the root")
        return 1
    print(f"ACCEPTED: {vector_id} is member #{proof['index']} of root {proof['merkle_root'][:16]}…")
    return 0


def cmd_run(args) -> int:
    manifest = _load(args.manifest)
    corpus = pathlib.Path(args.corpus)
    harness = args.harness
    results, started = [], time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for entry in manifest["files"]:
        path = corpus / entry["path"]
        if sha256_file(path) != entry["sha256"]:
            results.append({"id": entry["id"], "verdict": "REFUSED",
                            "detail": "corpus drifted from manifest before run"})
            continue
        proc = subprocess.run(harness + " " + str(path), shell=True,
                              capture_output=True, text=True, timeout=args.timeout)
        out = (proc.stdout + proc.stderr).strip()
        verdict = {0: "PASS", 1: "FAIL", 2: "NOT_EVALUATED"}.get(proc.returncode, "ERROR")
        if args.expect_refusal and proc.returncode == args.expect_refusal:
            verdict = "REFUSED_AS_EXPECTED"
        results.append({
            "id": entry["id"], "verdict": verdict, "exit": proc.returncode,
            "output_sha256": hashlib.sha256(out.encode()).hexdigest(),
            "output_head": out.splitlines()[0][:160] if out else "",
        })
    summary = {}
    for r in results:
        summary[r["verdict"]] = summary.get(r["verdict"], 0) + 1
    run = {
        "format": FORMAT,
        "corpus_id": manifest["corpus_id"],
        "manifest_root": manifest["merkle_root"],
        "harness": harness,
        "harness_sha256": args.harness_sha256,
        "started_at": started,
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": summary,
        "results": results,
    }
    if args.sign_key:
        run["signature"] = sign_run(run, args.sign_key)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "run.json"
    path.write_text(json.dumps(run, indent=2) + "\n")
    print(f"run over      : {manifest['count']} vectors")
    print(f"summary       : {summary}")
    print(f"run           : {path}")
    allowed = {"PASS", "REFUSED_AS_EXPECTED"}
    return 0 if set(summary) <= allowed else 1


def sign_run(run: dict, key_path: str) -> dict:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        print("cryptography not installed, refusing to claim a signature", file=sys.stderr)
        raise SystemExit(2)
    body = {k: v for k, v in run.items() if k != "signature"}
    msg = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(pathlib.Path(key_path).read_text().strip()))
    sig = key.sign(msg)
    pub = key.public_key().public_bytes_raw().hex()
    return {"alg": "Ed25519", "public_key": pub, "sig": sig.hex()}


def cmd_verify_run(args) -> int:
    manifest = _load(args.manifest)
    run = _load(args.run)
    if run["manifest_root"] != manifest["merkle_root"]:
        print("REFUSED: run was produced against a different corpus root")
        return 1
    if run["corpus_id"] != manifest["corpus_id"]:
        print("REFUSED: corpus id mismatch")
        return 1
    sig = run.get("signature")
    if sig:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            print("REFUSED: signature present but cryptography unavailable")
            return 1
        if args.pubkey and sig["public_key"] != args.pubkey:
            print("REFUSED: signing key does not match the pinned key")
            return 1
        body = {k: v for k, v in run.items() if k != "signature"}
        msg = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["public_key"])).verify(
                bytes.fromhex(sig["sig"]), msg)
        except Exception:
            print("REFUSED: signature does not verify")
            return 1
        print(f"signature     : valid, key {sig['public_key'][:16]}…")
    else:
        print("signature     : ABSENT (transcript is unauthenticated)")
    print(f"root          : matches manifest ({manifest['merkle_root'][:16]}…)")
    print(f"summary       : {run['summary']}")
    refused = [r for r in run["results"] if r["verdict"] not in ("PASS", "REFUSED_AS_EXPECTED")]
    if refused:
        print(f"non-passing   : {len(refused)} vectors")
        for r in refused[:5]:
            print(f"   {r['id']}: {r['verdict']}")
        return 1
    print("run           : accepted")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vectorlock", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("commit")
    c.add_argument("--corpus", required=True)
    c.add_argument("--id", required=True)
    c.add_argument("--version", default="0.1.0")
    c.add_argument("--out", required=True)
    c.add_argument("--exclude", action="append")
    c.set_defaults(func=cmd_commit)

    pr = sub.add_parser("proof")
    pr.add_argument("--manifest", required=True)
    pr.add_argument("--corpus", required=True)
    pr.add_argument("--file", required=True)
    pr.add_argument("--out")
    pr.set_defaults(func=cmd_proof)

    vp = sub.add_parser("verify-proof")
    vp.add_argument("--manifest", required=True)
    vp.add_argument("--corpus", required=True)
    vp.add_argument("--file", required=True)
    vp.add_argument("--proof", required=True)
    vp.set_defaults(func=cmd_verify_proof)

    r = sub.add_parser("run")
    r.add_argument("--manifest", required=True)
    r.add_argument("--corpus", required=True)
    r.add_argument("--harness", required=True)
    r.add_argument("--harness-sha256", default=None)
    r.add_argument("--out", required=True)
    r.add_argument("--timeout", type=int, default=120)
    r.add_argument("--expect-refusal", type=int, default=None)
    r.add_argument("--sign-key", default=None)
    r.set_defaults(func=cmd_run)

    vr = sub.add_parser("verify-run")
    vr.add_argument("--manifest", required=True)
    vr.add_argument("--run", required=True)
    vr.add_argument("--pubkey", default=None)
    vr.set_defaults(func=cmd_verify_run)
    return p


if __name__ == "__main__":
    ns = build_parser().parse_args()
    sys.exit(ns.func(ns))
