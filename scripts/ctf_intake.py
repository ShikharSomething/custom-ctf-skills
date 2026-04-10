#!/usr/bin/env python3
from __future__ import annotations
import argparse
import hashlib
import json
import mimetypes
import os
from pathlib import Path
from typing import Iterable

CATEGORY_HINTS = {
    "crypto": ["rsa", "aes", "cipher", "lwe", "ecc", "nonce", "prime"],
    "web": ["http", "url", "jwt", "cookie", "ssti", "xss", "sqli"],
    "pwn": ["elf", "libc", "overflow", "rop", "heap", "format string"],
    "reverse": ["apk", "wasm", "bytecode", "packed", "obfuscated"],
    "forensics": ["pcap", "memory", "dump", "image", "stego", "evtx"],
    "osint": ["who", "where", "social", "map", "geolocation"],
    "malware": ["c2", "beacon", "payload", "trojan", "loader"],
    "misc": ["jail", "encoding", "puzzle", "rf", "sdr"],
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def summarize_file(path: Path) -> dict:
    stat = path.stat()
    mime, _ = mimetypes.guess_type(path.name)
    return {
        "path": str(path),
        "size": stat.st_size,
        "sha256": sha256(path),
        "mime_guess": mime or "unknown",
        "suffix": path.suffix.lower(),
    }


def score_category(text: str) -> list[tuple[str, int]]:
    t = text.lower()
    scores = []
    for cat, hints in CATEGORY_HINTS.items():
        score = sum(1 for hint in hints if hint in t)
        scores.append((cat, score))
    return sorted(scores, key=lambda x: (-x[1], x[0]))


def gather(paths: Iterable[str]) -> list[dict]:
    items = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for child in sorted(x for x in p.rglob('*') if x.is_file()):
                items.append(summarize_file(child))
        elif p.is_file():
            items.append(summarize_file(p))
    return items


def main() -> int:
    ap = argparse.ArgumentParser(description='Generate a compact CTF intake summary.')
    ap.add_argument('paths', nargs='*', help='Files or directories to inventory')
    ap.add_argument('--description', default='', help='Challenge description or copied prompt')
    ap.add_argument('--json', action='store_true', help='Emit JSON instead of markdown')
    args = ap.parse_args()

    artifacts = gather(args.paths)
    evidence_text = args.description + ' ' + ' '.join(a['path'] for a in artifacts)
    ranked = score_category(evidence_text)

    summary = {
        "artifacts": artifacts,
        "category_ranking": ranked,
        "top_category": ranked[0][0] if ranked else "unknown",
        "description": args.description,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
        return 0

    print('# CTF intake summary')
    print(f"- top category guess: {summary['top_category']}")
    print(f"- artifacts: {len(artifacts)}")
    if args.description:
        print(f"- description: {args.description}")
    print('
## category ranking')
    for cat, score in ranked:
        print(f'- {cat}: {score}')
    print('
## artifacts')
    for a in artifacts:
        print(f"- {a['path']} | {a['size']} bytes | {a['suffix'] or '[no suffix]'} | {a['mime_guess']} | sha256={a['sha256'][:16]}...")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
