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


def test_run_and_verify_run_round_trip(committed, tmp_path):
    corpus, out, manifest = committed
    harness = tmp_path / "harness.py"
    harness.write_text(
        "import json,sys\n"
        "d=json.load(open(sys.argv[1]))\n"
        "sys.exit(1 if d.get('expect')=='refuse' else 0)\n")
    r = run("run", "--manifest", out / "manifest.json", "--corpus", corpus,
            "--harness", f"{sys.executable} {harness}", "--out", out,
            "--expect-refusal", 1)
    assert r.returncode == 0, r.stdout + r.stderr
    run_json = json.loads((out / "run.json").read_text())
    assert run_json["summary"] == {"PASS": 4, "REFUSED_AS_EXPECTED": 1}
    assert run_json["manifest_root"] == manifest["merkle_root"]
    v = run("verify-run", "--manifest", out / "manifest.json", "--run", out / "run.json")
    assert v.returncode == 0, v.stdout
    assert "accepted" in v.stdout


def test_run_refuses_when_the_corpus_drifted_after_commit(committed, tmp_path):
    corpus, out, _ = committed
    (corpus / "v0.json").write_text('{"vector": 0, "expect": "accept", "drifted": true}')
    harness = tmp_path / "h.py"
    harness.write_text("import sys; sys.exit(0)\n")
    r = run("run", "--manifest", out / "manifest.json", "--corpus", corpus,
            "--harness", f"{sys.executable} {harness}", "--out", out)
    run_json = json.loads((out / "run.json").read_text())
    assert any(x["verdict"] == "REFUSED" for x in run_json["results"])
    assert r.returncode == 1


def test_a_run_cannot_be_replayed_against_a_different_corpus(committed, corpus, tmp_path):
    _, out, _ = committed
    harness = tmp_path / "h.py"
    harness.write_text("import sys; sys.exit(0)\n")
    run("run", "--manifest", out / "manifest.json", "--corpus", corpus,
        "--harness", f"{sys.executable} {harness}", "--out", out)
    (corpus / "extra.json").write_text("{}")
    other = tmp_path / "other"
    run("commit", "--corpus", corpus, "--id", "test-corpus", "--out", other)
    r = run("verify-run", "--manifest", other / "manifest.json", "--run", out / "run.json")
    assert r.returncode == 1
    assert "different corpus root" in r.stdout
