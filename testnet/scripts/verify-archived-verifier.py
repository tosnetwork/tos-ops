#!/usr/bin/env python3
"""Check a public verifier source against its sanitized archive and provenance."""

import argparse
import json
from pathlib import Path

from transaction_archive import Refused, verify_citations, verify_sanitized


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--archive-file", required=True)
    parser.add_argument("--original", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    entries = [x for x in manifest["entries"] if x["archive_file"] == args.archive_file]
    if len(entries) != 1:
        raise Refused("archive file must have exactly one provenance entry")
    target = args.manifest.parent / args.archive_file
    if not target.resolve().is_relative_to(args.manifest.parent.resolve()):
        raise Refused("archive file escapes its manifest directory")
    verify_citations(args.manifest.parent.parent, entries[0])
    verify_sanitized(args.original.read_bytes(), target.read_bytes(), entries[0])
    print("public verifier source, cited hash and exact sanitization: PASS")


if __name__ == "__main__":
    main()
