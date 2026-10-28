"""Exact candidate installation and source receipts for isolated test commands.

The container needs Bash and GNU coreutils, not Python or a patch utility. The
host first applies every diff hunk exactly; the container verifies the original
bytes and atomically installs those exact resulting bytes. Test/dependency
patches must already have been prepared by the case script.
"""

import hashlib
from pathlib import Path
import shlex
from uuid import uuid4


PAYLOAD_PATH = "/kea-validation"
EVIDENCE_PATH = "/kea-evidence"
PROTOCOL = "exact-source-v1"
FIELDS = (
    "protocol", "nonce", "candidate_id", "step_name", "phase", "target_path",
    "source_path", "patch_hash", "original_source_hash", "source_hash",
)

SCRIPT = r'''#!/bin/bash
set -euo pipefail
payload=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$payload/environment.sh"
fail() { echo "Source attestation failed: $*" >&2; exit 86; }
hash() { sha256sum -- "$1" | cut -d ' ' -f 1; }
[[ $# == 2 ]] || fail 'expected apply|before|after and repository root'
phase=$1
root=$(cd -- "$2" && pwd -P) || fail 'repository root unavailable'
case "$phase" in apply|before|after) ;; *) fail 'invalid phase';; esac
file=$(readlink -f -- "$root/$TARGET_PATH") || fail 'target unavailable'
[[ "$file" == "$root/"* && -f "$file" && ! -L "$root/$TARGET_PATH" ]] || fail 'target must be a regular file inside the repository'
[[ "$file" != *$'\t'* && "$file" != *$'\n'* && "$file" != *$'\r'* ]] || fail 'invalid source path'
[[ $(hash "$payload/effective.patch") == "$PATCH_HASH" ]] || fail 'mounted diff hash mismatch'
[[ $(hash "$payload/original.source") == "$ORIGINAL_HASH" ]] || fail 'original snapshot hash mismatch'
[[ $(hash "$payload/fixed.source") == "$FIXED_HASH" ]] || fail 'candidate snapshot hash mismatch'
if [[ "$phase" == apply ]]; then
    [[ $(hash "$file") == "$ORIGINAL_HASH" ]] || fail 'container original differs from saved source (or candidate already applied)'
    temporary=$(mktemp "${file}.candidate.XXXXXX")
    trap 'rm -f -- "$temporary"' EXIT
    cat -- "$payload/fixed.source" > "$temporary"
    chmod --reference="$file" "$temporary"
    [[ $(hash "$temporary") == "$FIXED_HASH" ]] || fail 'candidate copy differs'
    mv -fT -- "$temporary" "$file"
    trap - EXIT
fi
actual=$(hash "$file")
[[ "$actual" == "$FIXED_HASH" ]] || fail 'tested source differs from the candidate'
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    exact-source-v1 "$NONCE" "$CANDIDATE_ID" "$STEP_NAME" "$phase" \
    "$TARGET_PATH" "$file" "$PATCH_HASH" "$ORIGINAL_HASH" "$actual" >> "$EVIDENCE_DIR/receipts.tsv"
'''


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def create_payload(directory, original, fixed, patch, target, candidate_id, step_name,
                   *, evidence_dir=EVIDENCE_PATH):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o755)
    expected = dict(
        protocol=PROTOCOL, nonce=uuid4().hex, candidate_id=str(candidate_id),
        step_name=step_name, target_path=target, patch_hash=digest(patch),
        original_source_hash=digest(original), source_hash=digest(fixed),
    )
    for value in expected.values():
        if not isinstance(value, str) or not value or any(c in value for c in "\t\n\r\x00"):
            raise ValueError("Invalid source attestation identity")
    for name, content in (("original.source", original), ("fixed.source", fixed),
                          ("effective.patch", patch), ("protocol.sh", SCRIPT)):
        (directory / name).write_bytes(content.encode("utf-8"))
        (directory / name).chmod(0o644)
    settings = dict(
        NONCE=expected["nonce"], CANDIDATE_ID=expected["candidate_id"],
        STEP_NAME=step_name, TARGET_PATH=target, PATCH_HASH=expected["patch_hash"],
        ORIGINAL_HASH=expected["original_source_hash"], FIXED_HASH=expected["source_hash"],
        EVIDENCE_DIR=str(evidence_dir),
    )
    (directory / "environment.sh").write_text(
        "\n".join(f"{key}={shlex.quote(value)}" for key, value in settings.items()) + "\n",
        encoding="utf-8",
    )
    (directory / "environment.sh").chmod(0o644)
    return expected


def verify_attestation(attestation, *, candidate_id, step_name, target,
                       patch_hash, original_hash, fixed_hash, image_id,
                       complete=True):
    """Validate both live receipts and archived receipts against saved artifacts."""
    if not isinstance(attestation, dict):
        raise ValueError("Missing container source attestation")
    expected = dict(
        protocol=PROTOCOL, candidate_id=str(candidate_id), step_name=step_name,
        target_path=target, patch_hash=patch_hash, original_source_hash=original_hash,
        source_hash=fixed_hash,
    )
    if any(attestation.get(key) != value for key, value in expected.items()):
        raise ValueError("Container source attestation differs from the candidate")
    if attestation.get("image_id") != image_id:
        raise ValueError("Container source attestation has a different image identity")
    nonce = attestation.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise ValueError("Missing source attestation nonce")
    receipts = attestation.get("receipts")
    if not isinstance(receipts, list) or len(receipts) > 3:
        raise ValueError("Invalid container source receipts")
    phases = [item.get("phase") for item in receipts if isinstance(item, dict)]
    if phases != ["apply", "before", "after"][:len(receipts)]:
        raise ValueError("Container source receipt phases are invalid")
    if complete and len(receipts) != 3:
        raise ValueError("Container did not attest candidate application and both test boundaries")
    for receipt in receipts:
        if any(receipt.get(key) != value for key, value in {**expected, "nonce": nonce}.items()):
            raise ValueError("Container receipt source/patch identity mismatch")
        path = receipt.get("source_path")
        if (not isinstance(path, str) or not path.startswith("/")
                or not path.endswith("/" + target)
                or any(c in path for c in "\t\n\r\x00")):
            raise ValueError("Invalid attested container target path")
    if len(receipts) == 3 and receipts[1]["source_path"] != receipts[2]["source_path"]:
        raise ValueError("Test boundaries refer to different source files")
    return attestation


def read_attestation(path, expected, image_id, *, complete):
    path = Path(path)
    if path.exists() and path.stat().st_size > 65536:
        raise ValueError("Oversized source receipt file")
    lines = path.read_text().splitlines() if path.exists() else []
    receipts = []
    for line in lines:
        values = line.split("\t")
        if len(values) != len(FIELDS):
            raise ValueError("Malformed container source receipt")
        receipts.append(dict(zip(FIELDS, values)))
    result = dict(expected, image_id=image_id, receipts=receipts)
    verify_attestation(
        result, candidate_id=expected["candidate_id"], step_name=expected["step_name"],
        target=expected["target_path"], patch_hash=expected["patch_hash"],
        original_hash=expected["original_source_hash"], fixed_hash=expected["source_hash"],
        image_id=image_id, complete=complete,
    )
    return result
