# Common CTF Triage Workflow

Use this before committing to a category.

## Minimum intake
- Capture the exact challenge name, category label, description, files, remote host/port, and any provided credentials.
- Record the expected flag format if known.
- Preserve originals before modifying or unpacking challenge files.

## 10-minute recon loop
1. Inventory every artifact: filenames, hashes, file types, entropy hints, embedded URLs, and obvious secrets.
2. Identify the trust boundary: local file, parser, remote socket, HTTP app, smart contract, or human OSINT target.
3. Test the simplest hypothesis first: known file signatures, obvious encodings, default creds, reused nonces, common bug classes.
4. Write down one falsifiable hypothesis at a time and the command used to test it.
5. Pivot quickly if evidence contradicts the current path.

## Evidence ledger
Track findings in four buckets:
- Facts: directly observed outputs, strings, headers, protocol behavior, cryptographic parameters.
- Guesses: theories not yet verified.
- Reusable primitives: leak, oracle, overwrite, traversal, nonce reuse, timing side channel, known plaintext.
- Blockers: missing dependency, unsupported format, remote instability, rate limit.

## Stop doing this
- Do not brute-force blindly before measuring the search space.
- Do not keep retrying the same failed idea with cosmetic variations.
- Do not discard partial primitives because they are "not the intended solution".

## Handoff format
When handing off between category skills, summarize:
- Challenge artifacts and remote endpoints
- Verified facts and failed approaches
- The best current primitive or hypothesis
- Exact commands/scripts already tried
