#!/usr/bin/env python3
"""Exercise the offline attestation CLI with a valid-shaped unknown signer."""

import base64
import hashlib
import json
import pathlib
import struct
import subprocess
import sys
import tempfile


def fixture_macho():
    data = bytearray(140)
    struct.pack_into("<I", data, 0, 0xFEEDFACF)
    struct.pack_into("<I", data, 4, 0x0100000C)
    struct.pack_into("<I", data, 12, 2)
    struct.pack_into("<I", data, 16, 1)
    struct.pack_into("<I", data, 20, 16)
    struct.pack_into("<I", data, 32, 0x1D)
    struct.pack_into("<I", data, 36, 16)
    struct.pack_into("<I", data, 40, 48)
    struct.pack_into("<I", data, 44, 92)
    struct.pack_into(">I", data, 48, 0xFADE0CC0)
    struct.pack_into(">I", data, 52, 92)
    struct.pack_into(">I", data, 56, 1)
    struct.pack_into(">I", data, 60, 0)
    struct.pack_into(">I", data, 64, 20)
    struct.pack_into(">I", data, 68, 0xFADE0C02)
    struct.pack_into(">I", data, 72, 72)
    struct.pack_into(">I", data, 76, 0)
    struct.pack_into(">I", data, 80, 0)
    struct.pack_into(">I", data, 84, 52)
    struct.pack_into(">I", data, 88, 44)
    struct.pack_into(">I", data, 96, 1)
    struct.pack_into(">I", data, 100, 1)
    data[104] = 20
    data[105] = 2
    data[107] = 12
    data[112:116] = b"app\0"
    return bytes(data)


def main():
    executable = pathlib.Path(sys.argv[1]).resolve()
    artifact_bytes = fixture_macho()
    digest = hashlib.sha256(artifact_bytes).hexdigest()
    payload = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "fixture-app", "digest": {"sha256": digest}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://example.invalid/buildtypes/ios-release/v1",
                "externalParameters": {"repository": "https://example.invalid/repo"},
                "resolvedDependencies": [
                    {
                        "uri": "git+https://example.invalid/repo",
                        "digest": {"gitCommit": "0123456789abcdef0123456789abcdef01234567"},
                    }
                ],
            },
            "runDetails": {
                "builder": {"id": "https://example.invalid/builders/unconfigured"}
            },
        },
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    envelope = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signatures": [
            {"keyid": "unknown-production-fixture", "sig": base64.b64encode(bytes(64)).decode("ascii")}
        ],
    }
    with tempfile.TemporaryDirectory(prefix="iu-p013d1-cli-") as temporary:
        root = pathlib.Path(temporary)
        artifact = root / "artifact.macho"
        attestation = root / "attestation.dsse.json"
        artifact.write_bytes(artifact_bytes)
        artifact.chmod(0o700)
        attestation.write_text(json.dumps(envelope, separators=(",", ":")), encoding="utf-8")
        attestation.chmod(0o600)
        result = subprocess.run(
            [str(executable), "provenance", "attestation", "verify", str(attestation), str(artifact)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 4, result.stdout + result.stderr
        for expected in (
            "Attestation syntax: VALID",
            "Attestation signature: UNKNOWN_SIGNER",
            "Signer identity: UNKNOWN (UNAVAILABLE)",
            "Attestation subject: MATCHED_DESCRIPTOR_SHA256",
            "Builder identity claimed: https://example.invalid/builders/unconfigured",
            "Builder identity trust: UNKNOWN_AUTHORITY",
            "Source revision: 0123456789abcdef0123456789abcdef01234567",
            "Build type: https://example.invalid/buildtypes/ios-release/v1",
            "Build-origin verification: BUILD_ORIGIN_UNVERIFIED",
            "Protected origin: UNKNOWN",
            "P009 Amethyst runtime: UNVERIFIED",
            "Launch boundary: NOT IMPLEMENTED",
            "Execution activation: DISABLED",
            "Operational authorization: FALSE",
        ):
            assert expected in result.stdout, result.stdout
        print("PASS: offline attestation CLI reports independent statuses and stays fail-closed")


if __name__ == "__main__":
    main()
