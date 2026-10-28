#!/usr/bin/env python3
"""Create isolated byte fixtures for the read-only planner integration test."""
import pathlib
import os
import socket
import struct
import subprocess
import sys
import tempfile


def le32(value):
    return struct.pack("<I", value)


def be32(value):
    return struct.pack(">I", value)


def macho(cpu=0x0100000C, signature="valid", adhoc=False):
    data = bytearray(160)
    data[0:4] = le32(0xFEEDFACF)
    data[4:8] = le32(cpu)
    data[12:16] = le32(2)
    if signature == "none":
        return bytes(data[:32])
    data[16:20] = le32(1)
    data[20:24] = le32(16)
    data[32:36] = le32(0x1D)
    data[36:40] = le32(16)
    data[40:44] = le32(48)
    size = 92 if signature != "empty" else 0
    data[44:48] = le32(size)
    if size:
        blob = 48
        data[blob:blob + 4] = be32(0xFADE0CC0)
        data[blob + 4:blob + 8] = be32(size - (1 if signature == "malformed" else 0))
        data[blob + 8:blob + 12] = be32(1)
        data[blob + 12:blob + 16] = be32(0)
        data[blob + 16:blob + 20] = be32(20)
        data[blob + 20:blob + 24] = be32(0xFADE0C02)
        data[blob + 24:blob + 28] = be32(72)
        data[blob + 28:blob + 32] = be32(0)
        data[blob + 32:blob + 36] = be32(2 if adhoc else 0)
        data[blob + 36:blob + 40] = be32(52)
        data[blob + 40:blob + 44] = be32(44)
        data[blob + 44:blob + 48] = be32(0)
        data[blob + 48:blob + 52] = be32(1)
        data[blob + 52:blob + 56] = be32(1)
        data[blob + 56] = 20
        data[blob + 57] = 2
        data[blob + 59] = 12
        data[blob + 64:blob + 68] = b"app\0"
    return bytes(data[:48 + size])


def main():
    test_binary = pathlib.Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="iu-planner-fixtures-") as temporary:
        root = pathlib.Path(temporary)
        fixtures = {
            "unsigned": macho(signature="none"),
            "parseable": macho(),
            "adhoc": macho(adhoc=True),
            "malformed": macho(signature="malformed"),
            "empty": macho(signature="empty"),
            "wrong-architecture": macho(cpu=0x01000007),
            "truncated": b"\xcf\xfa\xed\xfe\x0c\x00",
            "zero": b"",
            "random": b"",
            "bad-magic": b"not a Mach-O file" * 3,
            "huge-ncmds": bytearray(macho(signature="none")),
            "huge-sizeofcmds": bytearray(macho(signature="none")),
            "zero-cmdsize": bytearray(macho()),
            "overlapping-commands": bytearray(56),
            "oob-signature": bytearray(macho()),
            "wrong-filetype": bytearray(macho()),
            "bad-superblob-index": bytearray(macho()),
            "bad-codedirectory-length": bytearray(macho()),
            "conflicting-signatures": bytearray(160),
            "sha-abc": b"abc",
        }
        fixtures["random"] = bytes((i * 73 + 29) & 0xFF for i in range(257))
        fixtures["huge-ncmds"][16:20] = le32(0xFFFFFFFF)
        fixtures["huge-sizeofcmds"][20:24] = le32(0xFFFFFFFF)
        fixtures["zero-cmdsize"][36:40] = le32(0)
        fixtures["oob-signature"][40:44] = le32(0xFFFFFFF0)
        overlap = fixtures["overlapping-commands"]
        overlap[0:4] = le32(0xFEEDFACF)
        overlap[4:8] = le32(0x0100000C)
        overlap[12:16] = le32(2)
        overlap[16:20] = le32(2)
        overlap[20:24] = le32(24)
        overlap[32:36] = le32(0x1D)
        overlap[36:40] = le32(8)
        overlap[40:44] = le32(0x1D)
        overlap[44:48] = le32(16)
        fixtures["wrong-filetype"][12:16] = le32(6)
        fixtures["bad-superblob-index"][48 + 16:48 + 20] = be32(0xFFFFFFF0)
        fixtures["bad-codedirectory-length"][48 + 20 + 4:48 + 20 + 8] = be32(0xFFFFFFFF)
        conflict = fixtures["conflicting-signatures"]
        conflict[0:4] = le32(0xFEEDFACF)
        conflict[4:8] = le32(0x0100000C)
        conflict[12:16] = le32(2)
        conflict[16:20] = le32(2)
        conflict[20:24] = le32(32)
        for offset in (32, 48):
            conflict[offset:offset + 4] = le32(0x1D)
            conflict[offset + 4:offset + 8] = le32(16)
            conflict[offset + 8:offset + 12] = le32(64)
            conflict[offset + 12:offset + 16] = le32(92)
        fixtures["conflicting-signatures"] = bytes(conflict[:156])
        for name, content in fixtures.items():
            path = root / name
            path.write_bytes(content)
            path.chmod(0o700)
        os.mkfifo(root / "fifo")
        local_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        local_socket.bind(str(root / "socket"))
        local_socket.close()
        with (root / "oversized").open("wb") as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
        (root / "oversized").chmod(0o700)
        subprocess.run([str(test_binary), str(root)], check=True)


if __name__ == "__main__":
    main()
