#!/usr/bin/env python3
"""Host-only end-to-end tests for the local C daemon IPC endpoint."""
import os
import pathlib
import socket
import struct
import subprocess
import tempfile
import time

MAGIC = b"IUIP"
VERSION = 1
HEADER = 20
RESP = 0x8000


def frame(ty, body=b"", version=VERSION, magic=MAGIC, status=0):
    return struct.pack("!4sHHIII", magic, version, ty, 0x10203040, len(body), status) + body


def receive(sock):
    def exact(n):
        data = bytearray()
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise EOFError("peer closed")
            data.extend(chunk)
        return bytes(data)
    raw = exact(HEADER)
    magic, version, ty, reqid, length, status = struct.unpack("!4sHHIII", raw)
    body = exact(length)
    return magic, version, ty, reqid, status, body


def exchange(path, data):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(3)
        s.connect(str(path))
        s.sendall(data)
        return receive(s)


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def start(binary, path):
    proc = subprocess.Popen([binary, "--test-socket", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"daemon exited early: {proc.stderr.read().decode(errors='replace')}")
        if path.exists():
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.connect(str(path))
                return proc
            except OSError:
                pass
        time.sleep(0.02)
    proc.terminate()
    raise AssertionError("daemon did not create test socket")


def stop(proc, timeout=4):
    proc.terminate()
    proc.wait(timeout=timeout)
    check(proc.returncode == 0, "daemon did not shut down cleanly")


def lifecycle_rejection(binary, path, setup):
    setup(path)
    proc = subprocess.run([binary, "--test-socket", str(path)], timeout=3, capture_output=True)
    check(proc.returncode != 0, "unsafe existing socket path was accepted")


def main():
    binary = os.path.abspath("build/host/ios-unsandboxedd")
    cli = os.path.abspath("target/debug/ios-unsandboxed")
    with tempfile.TemporaryDirectory(prefix="iu-ipc-") as directory:
        root = pathlib.Path(directory)
        path = root / "daemon.sock"
        proc = start(binary, path)
        check(path.is_socket(), "test socket was not created")
        check(path.stat().st_mode & 0o777 == 0o600, "socket mode is not 0600")

        # PING and correlation id.
        m, v, ty, rid, code, body = exchange(path, frame(1))
        check((m, v, ty, rid, code) == (MAGIC, VERSION, 1 | RESP, 0x10203040, 0), "PING response header mismatch")
        check(body == b"\x050.1.0", "PING version payload mismatch")

        # GET_STATUS reports known product facts, never daemon-running-as-enabled.
        _, _, ty, _, code, body = exchange(path, frame(2))
        check(ty == (2 | RESP) and code == 0 and len(body) == 8, "GET_STATUS response invalid")
        check(body[0] == 1 and body[5:] == b"\0\0\0", "status overstated operational state")
        cli_status = subprocess.run([cli, "--test-socket", str(path), "status"], timeout=4, capture_output=True, text=True)
        check(cli_status.returncode == 0, f"Rust CLI status request failed: {cli_status.stderr}")
        check("Daemon: RUNNING" in cli_status.stdout and "Activation: DISABLED" in cli_status.stdout,
              "Rust CLI did not report daemon response fields")
        check("Amethyst compatibility: UNSUPPORTED PLATFORM" in cli_status.stdout,
              "Rust CLI did not report preflight state")

        # GET_PREFLIGHT is explicitly serialized and reports host unsupported.
        _, _, ty, _, code, body = exchange(path, frame(3))
        check(ty == (3 | RESP) and code == 7 and len(body) >= 24, "GET_PREFLIGHT missing/invalid")
        check(struct.unpack("!I", body[:4])[0] == 4, "Linux was not reported unsupported")

        # A non-root peer cannot request management; root still gets NOT_IMPLEMENTED.
        _, _, _, _, code, _ = exchange(path, frame(0x100))
        check(code == (4 if os.geteuid() == 0 else 3), "management authorization result incorrect")
        _, _, _, _, code, _ = exchange(path, frame(0x200))
        check(code == 3, "launch preparation was not denied")
        # A request-body identity claim is invalid and never changes socket credentials.
        _, _, _, _, code, _ = exchange(path, frame(0x100, struct.pack("!I", 0)))
        check(code == 2, "request-supplied identity was accepted")

        # Malformed frames are rejected or disconnected without taking down service.
        cases = [
            (frame(1, magic=b"BAD!"), 2),
            (frame(1, version=2), 1),
            (frame(0x777), 4),
            (frame(1, status=1), 2),
            (struct.pack("!4sHHIII", MAGIC, 1, 1, 7, 513, 0), 2),
        ]
        for raw, expected in cases:
            *_, code, _ = exchange(path, raw)
            check(code == expected, f"malformed request status {code}, expected {expected}")
        trailing = frame(1) + b"unexpected"
        *_, code, _ = exchange(path, trailing)
        check(code == 2, "unexpected trailing bytes were accepted")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(str(path)); s.sendall(b"IUIP\x00\x01")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(3); s.connect(str(path)); s.sendall(struct.pack("!4sHHIII", MAGIC, 1, 1, 4, 4, 0)+b"x")
            try: s.recv(1)
            except socket.timeout: raise AssertionError("truncated body exceeded timeout")
        # Partial writes are handled; stalled peer is bounded by the server's timeout.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(str(path))
            for byte in frame(1): s.send(bytes([byte]))
            check(receive(s)[4] == 0, "byte-wise partial request failed")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(3); s.connect(str(path)); s.sendall(b"IU")
            started = time.monotonic()
            try: s.recv(1)
            except socket.timeout: raise AssertionError("stalled client was not disconnected")
            check(time.monotonic() - started < 3, "stalled client timeout was unbounded")

        # Repeated bad connections do not take down the listener.
        for _ in range(8):
            try: exchange(path, b"x")
            except (EOFError, OSError, struct.error): pass
        check(exchange(path, frame(1))[4] == 0, "daemon unhealthy after malformed requests")

        # Duplicate server fails while owner is listening.
        duplicate = subprocess.run([binary, "--test-socket", str(path)], timeout=3, capture_output=True)
        check(duplicate.returncode != 0, "duplicate listener accepted")

        # Replacing the pathname before shutdown must not make this instance unlink it.
        moved = root / "owned.sock"
        path.rename(moved)
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        replacement.bind(str(path))
        stop(proc)
        check(path.is_socket(), "shutdown removed replacement socket")
        replacement.close(); path.unlink(); moved.unlink()

        lifecycle_rejection(binary, root / "ordinary", lambda p: p.write_text("preserve"))
        check((root / "ordinary").read_text() == "preserve", "ordinary file was modified")
        lifecycle_rejection(binary, root / "symlink", lambda p: p.symlink_to(root / "ordinary"))
        check((root / "symlink").is_symlink(), "symlink path was modified")

        stale = root / "stale.sock"
        stale_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale_listener.bind(str(stale)); stale_listener.close()
        stale_proc = start(binary, stale)
        check(exchange(stale, frame(1))[4] == 0, "stale project socket was not recovered")
        stop(stale_proc)
        check(not stale.exists(), "stale/recovered socket was not cleaned up")
    print("IPC integration tests passed (Linux peer credential path; same-UID host coverage).")


if __name__ == "__main__":
    main()
