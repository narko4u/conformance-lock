#!/usr/bin/env python3
"""Probe one sealed post-quantum vector against the WitnessOS verifier.

This harness only observes. It reports what the verifier did with the vector and
says nothing about whether that was the right thing to do:

  exit 0  the verifier accepted the manifest
  exit 1  the verifier refused the manifest
  exit 2  the verifier could not evaluate it

The expectation lives in the vector file (vector.expect = "accept" | "refuse") and
is judged by vectorlock during the run, so the transcript records the expectation,
the observation and the match between them separately.

Install: pip install witnessos-verifier
Usage  : ./harness.py <vector.json>
"""
import json
import pathlib
import sys
import tempfile

from witnessos_verifier.key_registry import KeyRecord, KeyRegistry
from witnessos_verifier.manifest import BatchManifest, verify_manifest


def main(path: str) -> int:
    bundle = json.loads(pathlib.Path(path).read_text())
    reg = KeyRegistry()
    for k in bundle["registry"]["keys"]:
        reg.add_key(KeyRecord(key_id=k["key_id"], public_key_hex=k["public_key"],
                              status=k["status"], algorithm=k["algorithm"]))
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(bundle["manifest"], fh)
        tmp = fh.name
    try:
        res = verify_manifest(BatchManifest.from_file(pathlib.Path(tmp)), reg)
    except Exception as exc:                                  # verifier itself blew up
        print(f"UNEVALUATED harness could not evaluate: {type(exc).__name__}: {exc}")
        return 2
    if res.valid:
        print(f"ACCEPTED suite={res.signature_suite} counter_ok={res.countersignature_valid}")
        return 0
    first = (res.errors or ["refused without a reason string"])[0]
    print(f"REFUSED {first}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
