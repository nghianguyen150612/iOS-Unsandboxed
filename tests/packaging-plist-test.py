#!/usr/bin/env python3
"""Host syntax and contract checks for the passive rootful LaunchDaemon plist."""
import pathlib
import plistlib


path = pathlib.Path("packaging/rootful/com.ios-unsandboxed.daemon.plist")
with path.open("rb") as source:
    job = plistlib.load(source)

assert job["Label"] == "com.ios-unsandboxed.daemon"
assert job["ProgramArguments"] == [
    "/usr/local/bin/ios-unsandboxedd",
    "--serve",
]
assert job["UserName"] == "root"
assert job["GroupName"] == "wheel"
assert job["RunAtLoad"] is True
assert job["KeepAlive"] is False
assert job["StandardOutPath"] == "/var/log/ios-unsandboxed/daemon.stdout.log"
assert job["StandardErrorPath"] == "/var/log/ios-unsandboxed/daemon.stderr.log"
assert "Sockets" not in job
state = pathlib.Path("packaging/rootful/install-state.example").read_text()
assert state == (
    "ios-unsandboxed-state\n"
    "schema_version=1\n"
    "service_installation=installed\n"
    "execution_activation=disabled\n"
)
print("LaunchDaemon plist and disabled-state example validated (host plistlib only).")
