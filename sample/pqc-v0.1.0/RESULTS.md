# Post-quantum verifier conformance set, v0.1.0

Sealed 2026-10-19. Ten vectors, run against the published WitnessOS verifier. Two are revealed here, eight are held back.

| Field | Value |
|---|---|
| Corpus root (merkle) | `d22923ac17d0f1e2244f5dc2dc9913e4c95c446a5b6daa947fe21447c6a38b19` |
| Vectors | 10, of which 2 are controls and 8 are attacks |
| Result | 10 of 10 behaved as required |
| Harness digest | `dd71fbee2b152ff2011649ea2ae75360d4be48d301db73940e4deb7eee06d0e4` |
| Signature | Ed25519 over the run transcript, key `d516d34b4040c1e2…` |
| Revealed | `pqc-ctl-02`, `pqc-atk-02`, each with an inclusion proof in this directory |

## What was tested

Controls prove the verifier still accepts honest records. Every attack has the same shape: a record that was genuinely signed, then edited by someone who cannot re-sign it. That is the realistic adversary, not a fuzzer.

| ID | Class | What it tests | Verdict |
|---|---|---|---|
| `pqc-ctl-01` | control | Valid hybrid record, Ed25519 and ML-DSA-65 both genuine over the same bytes | Accepted |
| `pqc-ctl-02` | control | Classical record with no suite declared | Accepted |
| `pqc-atk-01` | attack | Suite rewritten to classical while the post-quantum half stays in place | Refused, names the suite |
| `pqc-atk-02` | attack | Valid ML-DSA-65 signature over different bytes | Refused, invalid for scheme |
| `pqc-atk-03` | attack | Correct bytes signed by a key the registry does not hold | Refused, invalid for scheme |
| `pqc-atk-04` | attack | Post-quantum half attributed to the primary key id | Refused, countersigner is the primary key |
| `pqc-atk-05` | attack | Suite label claims the other order of the same two schemes | Refused, primary half invalid |
| `pqc-atk-06` | attack | Batch root rewritten after signing | Refused, primary half invalid |
| `pqc-atk-07` | attack | Event id added outside the signed range | Refused, primary half invalid |
| `pqc-atk-08` | attack | Sequence window narrowed to hide the second event | Refused, primary half invalid |

Every refusal carries a reason string. None is a traceback and none is a silent pass. The downgrade attempt, for instance, answers: *"Manifest declares signature suite ed25519, which names fewer than two schemes."*

## Verify the seal yourself

Two commands, both offline. The first checks the revealed vectors belong to the sealed root. The second is the one a buyer of the full set runs against what they receive.

```bash
python3 vectorlock.py verify-proof --manifest sample/pqc-v0.1.0/manifest.json \
  --corpus sample/pqc-v0.1.0 --file sample/pqc-v0.1.0/pqc-atk-02.json \
  --proof sample/pqc-v0.1.0/pqc-atk-02.proof.json

python3 vectorlock.py verify-proof --manifest sample/pqc-v0.1.0/manifest.json \
  --corpus sample/pqc-v0.1.0 --file sample/pqc-v0.1.0/pqc-ctl-02.json \
  --proof sample/pqc-v0.1.0/pqc-ctl-02.proof.json
```

Both are expected to print `ACCEPTED`, naming the member index and the root prefix. Substitute one revealed vector for the other and the check must refuse, because the file digest no longer matches the commitment.

## What this proves and what it does not

Proves: a corpus with exactly this root existed at the sealed time. A harness with the digest above produced these ten verdicts against exactly that corpus. The two revealed vectors are members of it. Change one byte of any vector and the root breaks.

Does not prove: that these ten are sufficient or that no other downgrade path exists. It also does not prove the harness is free of special-casing for its own corpus. Two vectors are revealed so the method can be attacked rather than trusted.

Scope of v0.1.0: the signature and manifest surface, which is where post-quantum downgrade risk lives. The timestamp and retention layer of a full E4 bundle is not covered yet. We will say v0.2 when it is.

## Terms

| Tier | What you get |
|---|---|
| Floor set | The two revealed vectors and the harness. Free permanently, attribution required. |
| Full set | All ten vectors with inclusion proofs against the sealed root. By quote. |
| Certification run | We run the set against your implementation and publish a signed verdict naming every refusal. By quote. |

Prices are AUD excluding GST and are set from [witnessos.com.au/pricing](https://witnessos.com.au/pricing). Contact [contact@empirelabs.com.au](mailto:contact@empirelabs.com.au).

---

Security Division, Empire Labs Pty Ltd
