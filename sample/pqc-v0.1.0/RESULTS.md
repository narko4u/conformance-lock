# Post-quantum verifier conformance set, v0.1.0

Sealed 2026-10-19, transcript re-issued 2026-10-20. Ten vectors, run against the published WitnessOS verifier. Two are revealed here, eight are held back.

| Field | Value |
|---|---|
| Corpus root (merkle) | `d22923ac17d0f1e2244f5dc2dc9913e4c95c446a5b6daa947fe21447c6a38b19` |
| Vectors | 10 sealed, 2 revealed, 8 held back |
| Result | 2 accepted as required, 8 refused as required |
| Harness digest | `6611327f42a1de15289cfeb2a0728be40e142d20a9809e14ef4f9d94f4f9ce16` |
| Verification key | `d516d34b4040c1e2a06ad51a6cf220edcd1acc67e32c853e589b4a529f5564c4` |
| Transcript | `run.json` in this directory, Ed25519 signed |
| DOI | [10.5281/zenodo.23487396](https://doi.org/10.5281/zenodo.23487396) |

## What was tested

Two controls must be accepted. Eight attacks must be refused. Every attack is a record that was genuinely signed and then edited by someone who cannot re-sign it.

| Vector | Class | What it does | Required result |
|---|---|---|---|
| `pqc-ctl-01` | control | valid hybrid record, suite `ed25519+ml-dsa-65` | accept |
| `pqc-ctl-02` | control | valid classical record, suite `v1` | accept |
| `pqc-atk-01` | downgrade | suite relabelled to `ed25519` with the post-quantum half still attached | refuse |
| `pqc-atk-02` | forgery | valid ML-DSA-65 signature over the wrong bytes | refuse |
| `pqc-atk-03` | key binding | correct bytes signed by an ML-DSA-65 key the registry does not hold | refuse |
| `pqc-atk-04` | key confusion | post-quantum half attributed to the primary key | refuse |
| `pqc-atk-05` | relabel | suite order flipped to `ml-dsa-65+ed25519` | refuse |
| `pqc-atk-06` | integrity | batch root rewritten after signing | refuse |
| `pqc-atk-07` | membership | event id added outside the signed range | refuse |
| `pqc-atk-08` | windowing | sequence window narrowed to hide the second event | refuse |

The transcript carries the expectation, the observation and the match for each vector, plus the verifier's own reason string. Nothing is summarised into a single number that a reader has to trust.

## Verify it yourself

The verifier is a published package, so the whole chain can be checked offline.

```bash
pip install witnessos-verifier
python3 vectorlock.py verify-run \
  --manifest sample/pqc-v0.1.0/manifest.json \
  --run sample/pqc-v0.1.0/run.json \
  --pubkey d516d34b4040c1e2a06ad51a6cf220edcd1acc67e32c853e589b4a529f5564c4
```

Expected: `signature: valid`, `root: matches manifest`, `coverage: all 10 sealed vectors present exactly once`, `run: accepted`.

Then check the two revealed vectors really belong to that corpus:

```bash
python3 vectorlock.py verify-proof \
  --manifest sample/pqc-v0.1.0/manifest.json \
  --corpus sample/pqc-v0.1.0 \
  --file sample/pqc-v0.1.0/pqc-atk-02.json \
  --proof sample/pqc-v0.1.0/pqc-atk-02.proof.json
```

And check the method catches a substitution: replace `pqc-ctl-02.json` with `pqc-atk-02.json` and rerun its proof. It refuses with `file changed since commitment`.

You can also run the published harness against either revealed vector to see the verifier's own behaviour on that case:

```bash
python3 sample/pqc-v0.1.0/harness.py sample/pqc-v0.1.0/pqc-atk-02.json
```

## What this proves

- A corpus with exactly this root existed at the sealed time. A harness with the digest above produced these ten verdicts against exactly that corpus.
- Each revealed vector is a member of that corpus, proven by inclusion rather than by our word.
- Nobody, including us, can now swap or edit a held-back vector without breaking the root.

## What this does not prove

- That these ten are sufficient or that no other downgrade path exists.
- That the harness is free of special-casing for its own corpus.
- That a green result on all ten means a given implementation is secure. Conformance is not assurance.

The harness is a probe. It reports what the verifier did and says nothing about whether that was correct. The expectation for each vector lives in the vector file and is judged by `vectorlock`, so an implementation that wrongly accepts an attack vector produces `MISMATCH` and cannot produce a green run.

## Held back

Eight vectors, by licence. Their digests are public in `manifest.json`, so their existence and their number are fixed. What is private is what they contain. The reason to buy is that they are the same eight that produced this result.

Contact: contact@empirelabs.com.au

Security Division, Empire Labs Pty Ltd
