import json
import pathlib
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
VL = ROOT / "vectorlock.py"


def run(*args, cwd=None):
    return subprocess.run([sys.executable, str(VL), *map(str, args)],
                          capture_output=True, text=True, cwd=cwd)


@pytest.fixture()
def corpus(tmp_path):
    c = tmp_path / "corpus"
    c.mkdir()
    for i in range(5):
        (c / f"v{i}.json").write_text(json.dumps({"vector": i, "expect": "refuse" if i == 4 else "accept"}))
    return c


@pytest.fixture()
def committed(corpus, tmp_path):
    out = tmp_path / "out"
    r = run("commit", "--corpus", corpus, "--id", "test-corpus", "--version", "1.2.3", "--out", out)
    assert r.returncode == 0, r.stderr
    return corpus, out, json.loads((out / "manifest.json").read_text())


@pytest.fixture()
def signing_key(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    path = tmp_path / "signing-key.hex"
    path.write_text(key.private_bytes_raw().hex())
    path.chmod(0o600)
    pub = key.public_key().public_bytes_raw().hex()
    return path, pub


def honest_harness(tmp_path):
    harness = tmp_path / "harness.py"
    harness.write_text(
        "import json,sys\n"
        "d=json.load(open(sys.argv[1]))\n"
        "sys.exit(1 if d.get('expect')=='refuse' else 0)\n")
    return harness


def resign(run_json, key_path):
    """Re-sign a tampered transcript, so the structural checks get exercised.

    A mutation without a fresh signature is caught by the signature check first,
    which is correct but hides whether the coverage and summary checks work.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_path.read_text().strip()))
    body = {k: v for k, v in run_json.items() if k != "signature"}
    msg = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    run_json["signature"] = {
        "alg": "Ed25519",
        "public_key": key.public_key().public_bytes_raw().hex(),
        "sig": key.sign(msg).hex(),
    }
    return run_json


def test_commit_records_every_file_with_a_root(committed):
    _, out, manifest = committed
    assert manifest["format"] == "vectorlock/v1"
    assert manifest["count"] == 5
    assert len(manifest["merkle_root"]) == 64
    assert {f["id"] for f in manifest["files"]} == {f"v{i}.json" for i in range(5)}


def test_proof_validates_for_each_member(committed, tmp_path):
    corpus, out, manifest = committed
    for i in range(5):
        proof_path = tmp_path / f"proof{i}.json"
        assert run("proof", "--manifest", out / "manifest.json", "--corpus", corpus,
                   "--file", corpus / f"v{i}.json", "--out", proof_path).returncode == 0
        r = run("verify-proof", "--manifest", out / "manifest.json", "--corpus", corpus,
                "--file", corpus / f"v{i}.json", "--proof", proof_path)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "ACCEPTED" in r.stdout


def test_tampered_vector_is_refused(committed, tmp_path):
    corpus, out, _ = committed
    proof_path = tmp_path / "proof.json"
    run("proof", "--manifest", out / "manifest.json", "--corpus", corpus,
        "--file", corpus / "v2.json", "--out", proof_path)
    (corpus / "v2.json").write_text(json.dumps({"vector": 2, "expect": "accept", "edited": True}))
    r = run("verify-proof", "--manifest", out / "manifest.json", "--corpus", corpus,
            "--file", corpus / "v2.json", "--proof", proof_path)
    assert r.returncode == 1
    assert "REFUSED" in r.stdout


def test_renaming_a_vector_cannot_reuse_another_proof(committed, tmp_path):
    corpus, out, _ = committed
    proof_path = tmp_path / "proof.json"
    run("proof", "--manifest", out / "manifest.json", "--corpus", corpus,
        "--file", corpus / "v1.json", "--out", proof_path)
    shutil.copy(corpus / "v1.json", corpus / "v3.json")
    r = run("verify-proof", "--manifest", out / "manifest.json", "--corpus", corpus,
            "--file", corpus / "v3.json", "--proof", proof_path)
    assert r.returncode == 1, "a proof for v1 must not verify for v3"


def test_proof_against_a_foreign_manifest_is_refused(committed, corpus, tmp_path):
    _, out, _ = committed
    proof_path = tmp_path / "proof.json"
    run("proof", "--manifest", out / "manifest.json", "--corpus", corpus,
        "--file", corpus / "v1.json", "--out", proof_path)
    other = tmp_path / "other"
    (corpus / "v9.json").write_text("{}")
    assert run("commit", "--corpus", corpus, "--id", "other", "--out", other).returncode == 0
    r = run("verify-proof", "--manifest", other / "manifest.json", "--corpus", corpus,
            "--file", corpus / "v1.json", "--proof", proof_path)
    assert r.returncode == 1
    assert "root" in r.stdout


def test_run_and_verify_run_round_trip(committed, tmp_path, signing_key):
    corpus, out, manifest = committed
    key, pub = signing_key
    harness = honest_harness(tmp_path)
    r = run("run", "--manifest", out / "manifest.json", "--corpus", corpus,
            "--harness", f"{sys.executable} {harness}", "--out", out,
            "--expect-path", "expect", "--sign-key", key)
    assert r.returncode == 0, r.stdout + r.stderr
    run_json = json.loads((out / "run.json").read_text())
    assert run_json["summary"] == {"PASS": 4, "REFUSED_AS_EXPECTED": 1}
    assert run_json["manifest_root"] == manifest["merkle_root"]
    assert run_json["harness_sha256"] is not None
    v = run("verify-run", "--manifest", out / "manifest.json", "--run", out / "run.json",
            "--pubkey", pub)
    assert v.returncode == 0, v.stdout
    assert "accepted" in v.stdout
    assert "all 5 sealed vectors present exactly once" in v.stdout


def test_attack_vector_unexpectedly_accepted_is_not_green(committed, tmp_path, signing_key):
    """A harness that accepts everything must never produce a green conformance run."""
    corpus, out, _ = committed
    key, _ = signing_key
    lazy = tmp_path / "lazy.py"
    lazy.write_text("import sys; sys.exit(0)\n")
    r = run("run", "--manifest", out / "manifest.json", "--corpus", corpus,
            "--harness", f"{sys.executable} {lazy}", "--out", out,
            "--expect-path", "expect", "--sign-key", key)
    run_json = json.loads((out / "run.json").read_text())
    assert r.returncode == 1, "a vector expecting refusal must not pass when accepted"
    assert run_json["results"][4]["verdict"] == "MISMATCH"


def test_transcript_that_omits_a_sealed_vector_is_refused(committed, tmp_path, signing_key):
    corpus, out, _ = committed
    key, pub = signing_key
    harness = honest_harness(tmp_path)
    run("run", "--manifest", out / "manifest.json", "--corpus", corpus,
        "--harness", f"{sys.executable} {harness}", "--out", out,
        "--expect-path", "expect", "--sign-key", key)
    run_json = json.loads((out / "run.json").read_text())
    run_json["results"] = run_json["results"][:3]
    resign(run_json, key)
    (out / "run.json").write_text(json.dumps(run_json, indent=2))
    v = run("verify-run", "--manifest", out / "manifest.json", "--run", out / "run.json",
            "--pubkey", pub)
    assert v.returncode == 1
    assert "omits" in v.stdout


def test_duplicate_results_are_refused(committed, tmp_path, signing_key):
    corpus, out, _ = committed
    key, pub = signing_key
    harness = honest_harness(tmp_path)
    run("run", "--manifest", out / "manifest.json", "--corpus", corpus,
        "--harness", f"{sys.executable} {harness}", "--out", out,
        "--expect-path", "expect", "--sign-key", key)
    run_json = json.loads((out / "run.json").read_text())
    run_json["results"][1] = dict(run_json["results"][0])
    resign(run_json, key)
    (out / "run.json").write_text(json.dumps(run_json, indent=2))
    v = run("verify-run", "--manifest", out / "manifest.json", "--run", out / "run.json",
            "--pubkey", pub)
    assert v.returncode == 1
    assert "repeats" in v.stdout or "omits" in v.stdout


def test_unpinned_transcript_is_refused_by_default(committed, tmp_path):
    corpus, out, _ = committed
    harness = honest_harness(tmp_path)
    run("run", "--manifest", out / "manifest.json", "--corpus", corpus,
        "--harness", f"{sys.executable} {harness}", "--out", out,
        "--expect-path", "expect")
    v = run("verify-run", "--manifest", out / "manifest.json", "--run", out / "run.json")
    assert v.returncode == 1
    assert "no signature" in v.stdout.lower() or "pinned" in v.stdout.lower()


def test_summary_that_disagrees_with_results_is_refused(committed, tmp_path, signing_key):
    corpus, out, _ = committed
    key, pub = signing_key
    harness = honest_harness(tmp_path)
    run("run", "--manifest", out / "manifest.json", "--corpus", corpus,
        "--harness", f"{sys.executable} {harness}", "--out", out,
        "--expect-path", "expect", "--sign-key", key)
    run_json = json.loads((out / "run.json").read_text())
    run_json["summary"] = {"PASS": 5}
    resign(run_json, key)
    (out / "run.json").write_text(json.dumps(run_json, indent=2))
    v = run("verify-run", "--manifest", out / "manifest.json", "--run", out / "run.json",
            "--pubkey", pub)
    assert v.returncode == 1
    assert "summary does not match" in v.stdout


def test_declared_harness_digest_must_match_the_executed_harness(committed, tmp_path):
    corpus, out, _ = committed
    harness = honest_harness(tmp_path)
    r = run("run", "--manifest", out / "manifest.json", "--corpus", corpus,
            "--harness", f"{sys.executable} {harness}", "--out", out,
            "--expect-path", "expect", "--harness-sha256", "0" * 64)
    assert r.returncode != 0
    assert "does not match the executed harness" in (r.stdout + r.stderr)


def test_run_refuses_when_the_corpus_drifted_after_commit(committed, tmp_path):
    corpus, out, _ = committed
    (corpus / "v0.json").write_text('{"vector": 0, "expect": "accept", "drifted": true}')
    harness = tmp_path / "h.py"
    harness.write_text("import sys; sys.exit(0)\n")
    r = run("run", "--manifest", out / "manifest.json", "--corpus", corpus,
            "--harness", f"{sys.executable} {harness}", "--out", out,
            "--expect-path", "expect")
    run_json = json.loads((out / "run.json").read_text())
    assert any(x["verdict"] == "REFUSED" for x in run_json["results"])
    assert r.returncode == 1


def test_a_run_cannot_be_replayed_against_a_different_corpus(committed, corpus, tmp_path):
    _, out, _ = committed
    harness = tmp_path / "h.py"
    harness.write_text("import sys; sys.exit(0)\n")
    run("run", "--manifest", out / "manifest.json", "--corpus", corpus,
        "--harness", f"{sys.executable} {harness}", "--out", out,
        "--expect-path", "expect")
    (corpus / "extra.json").write_text("{}")
    other = tmp_path / "other"
    run("commit", "--corpus", corpus, "--id", "test-corpus", "--out", other)
    r = run("verify-run", "--manifest", other / "manifest.json", "--run", out / "run.json",
            "--allow-unpinned")
    assert r.returncode == 1
    assert "different corpus root" in r.stdout
