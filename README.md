# conformance-lock

Commit to a private conformance corpus, publish the signed run, keep the contents.

This repository holds two things: the method and one worked example of it. The method is free. The example is the free sample of a corpus we sell.

Archived, citable release: **v0.1.0**, DOI [10.5281/zenodo.23487396](https://doi.org/10.5281/zenodo.23487396).

---

## The problem this solves

A private test corpus plus a public claim that it works is worth nothing. "We have N attack vectors and they all pass" is the move every vendor makes. It has nothing falsifiable behind it. Hashing an unpublished file barely improves it, because a hash only proves that a file existed.

What makes a private corpus credible is three things together:

1. a commitment you cannot wriggle out of later,
2. a run anyone can check,
3. a small revealed floor that lets a stranger falsify your method today.

## The mechanism

**Commitment.** Every vector is hashed individually. The hashes combine into one merkle root over the sorted leaves. We publish the manifest: identifiers, sizes, digests, root. No contents.

**Signed transcript.** We run a harness across the corpus and publish a verdict per vector, bound to the manifest root, signed with Ed25519 so the results cannot be edited afterwards.

**Anchor.** A timestamp authority record over the manifest and transcript, so "we had this corpus and this result on this date" is not a claim about our own clock.

**Floor set.** A few vectors are revealed in full, with inclusion proofs against the same root. That is what lets an outsider attack the method rather than trust the promise. A proof shows each revealed file is a member of the sealed corpus, so we cannot reveal a soft vector and sell something else.

## The property that makes it work

A buyer of the full corpus recomputes the merkle root from what they received. It must equal the root published here. If one vector was swapped after the run, the roots diverge and the sale is void.

That is the whole commercial argument: **you are buying the corpus that provably produced the published results, not one that resembles it.**

## What this repository proves and what it does not

Proves:

- a corpus with exactly this root existed at the sealed time,
- a harness with the published digest produced these verdicts against exactly that corpus,
- the revealed vectors are members of that corpus,
- no vector can be changed, added or removed without breaking the root.

Does not prove:

- the vectors are well designed or hard,
- the harness is free of special-casing for its own corpus,
- that a vector marked `NOT_EVALUATED` was ever tested by anyone.

Say that ceiling out loud wherever the results are published. Our rule is the same one we apply to evidence grading: a record cannot grade itself.

## What is free and what is paid

| Tier | What you get | Terms |
|---|---|---|
| **Method** | This repository: the tool, the tests, the doctrine | Free, Apache-2.0 |
| **Floor set** | The revealed vectors in `sample/`, with inclusion proofs | Free permanently, attribution required |
| **Full corpus** | The vectors held back, delivered with inclusion proofs against the sealed root | By quote, AUD excluding GST |
| **Certification run** | We run the corpus against your implementation and publish a signed verdict naming every refusal | By quote, AUD excluding GST |

Pricing is canonical at [witnessos.com.au/pricing](https://witnessos.com.au/pricing). We do not publish made-up numbers in a README and we do not discount on Twitter.

The rule behind the split: the free sample is the proof of method, so the paid corpus is credible. Without a falsifiable floor, a private corpus is an assertion.

## Working with the tool

```bash
# commit a private corpus: publishes identifiers, sizes and digests, never contents
python3 vectorlock.py commit --corpus ./corpus --id my-corpus --version 0.1.0 --out ./published

# run it, signed
python3 vectorlock.py run --manifest ./published/manifest.json --corpus ./corpus \
  --harness "./harness.py" --expect-path expect --out ./published --sign-key ./signing-key.hex

# a stranger checks the transcript
python3 vectorlock.py verify-run --manifest ./published/manifest.json --run ./published/run.json \
  --pubkey <pinned-key-hex>

# and checks one revealed vector is a member of the sealed corpus
python3 vectorlock.py proof --manifest ./published/manifest.json --corpus ./corpus \
  --file ./corpus/vector-01.json --out ./published/proof-01.json
python3 vectorlock.py verify-proof --manifest ./published/manifest.json --corpus ./corpus \
  --file ./corpus/vector-01.json --proof ./published/proof-01.json
```

`pytest tests/` covers commitment, inclusion proofs, tamper refusal, a renamed-vector replay, a foreign-manifest proof and the rule that a run which skipped vectors is never reported as green.

### Probe and judge are separate

A harness should only observe. It exits 0 when the implementation accepted the vector, 1 when it refused and 2 when it could not evaluate. The expectation belongs in the vector itself, for example `"expect": "refuse"`, read with `--expect-path`. `vectorlock` then records the expectation, the observation and the match, so an attack vector that is wrongly accepted is `MISMATCH` and can never produce a green run.

A harness that judges instead of observing hides that distinction. The worked example in this repository publishes its harness so the judgement can be read.

### A transcript is only accepted with a pinned key

`verify-run` refuses an unsigned transcript. It also refuses a signed one unless `--pubkey` names the key you already trust. A signature made by a key carried inside the same document proves nothing: anyone can sign their own all-green report. Pass `--allow-unpinned` to inspect a transcript without accepting it as proof.

The transcript must also cover the manifest exactly. Missing vectors, duplicate entries and a summary that disagrees with the results are all refused.

## The worked example in this repository

`sample/pqc-v0.1.0/` is a post-quantum verifier conformance set. Ten vectors, two revealed, eight held back, sealed on 2026-10-19.

| Field | Value |
|---|---|
| Corpus root | `d22923ac17d0f1e2244f5dc2dc9913e4c95c446a5b6daa947fe21447c6a38b19` |
| Result | 2 accepted as required, 8 refused as required |
| Harness digest | `6611327f42a1de15289cfeb2a0728be40e142d20a9809e14ef4f9d94f4f9ce16` |
| Verification key | `d516d34b4040c1e2a06ad51a6cf220edcd1acc67e32c853e589b4a529f5564c4` |
| Revealed | `pqc-ctl-02` (classical control), `pqc-atk-02` (signature over wrong bytes) |

Check the seal yourself, offline:

```bash
python3 vectorlock.py verify-run --manifest sample/pqc-v0.1.0/manifest.json \
  --run sample/pqc-v0.1.0/run.json \
  --pubkey d516d34b4040c1e2a06ad51a6cf220edcd1acc67e32c853e589b4a529f5564c4

python3 vectorlock.py verify-proof --manifest sample/pqc-v0.1.0/manifest.json \
  --corpus sample/pqc-v0.1.0 --file sample/pqc-v0.1.0/pqc-atk-02.json \
  --proof sample/pqc-v0.1.0/pqc-atk-02.proof.json
```

Read `sample/pqc-v0.1.0/RESULTS.md` for the vector table, the reason strings each refusal produced and the stated ceiling.

## Rules the tool encodes

- **Never generate vectors in a public repository.** Branches and history leak. Generate private, publish commitments.
- **Never publish a hash-only claim.** Unfalsifiable without a reveal path, so it reads as marketing.
- **Never report a run as green when it skipped vectors.** `NOT_EVALUATED` exits non-zero, deliberately.
- **Publish the harness digest** beside the verdicts, so the reader knows what judged them.

---

Security Division, Empire Labs Pty Ltd
Townsville, Queensland, Australia
[contact@empirelabs.com.au](mailto:contact@empirelabs.com.au) · [empirelabs.com.au](https://empirelabs.com.au) · [witnessos.com.au](https://witnessos.com.au)
