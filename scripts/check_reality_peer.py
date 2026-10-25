#!/usr/bin/env python3
"""Build and run the pinned REALITY regression in a loopback-only namespace."""
import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", type=pathlib.Path, required=True,
                        help="Xray 26.10.21 Linux x86-64 binary; checksum is verified by the test")
    parser.add_argument("--scratch-root", type=pathlib.Path)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent.parent
    for tool in ("cargo", "bwrap", "timeout"):
        if shutil.which(tool) is None:
            raise RuntimeError(f"required tool unavailable: {tool}; no skipped pass")
    peer = args.peer.resolve(strict=True)
    print("[1/2] Build pinned REALITY peer regression", flush=True)
    command = ["timeout", "--kill-after=3s", "180s", "cargo", "test", "--locked",
               "-p", "meow-proxy", "--no-default-features", "--features", "vless,vless-vision",
               "--test", "reality_xray_loopback", "--no-run", "--message-format=json"]
    executable = None
    with subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                print(line, end="", flush=True)
                continue
            if message.get("reason") == "compiler-message":
                print(message["message"].get("rendered", ""), end="", flush=True)
            if (message.get("reason") == "compiler-artifact"
                    and message.get("target", {}).get("name") == "reality_xray_loopback"
                    and message.get("executable")):
                executable = pathlib.Path(message["executable"])
        if process.wait() != 0:
            raise RuntimeError("peer regression build failed")
    if executable is None:
        raise RuntimeError("peer regression executable missing; no skipped pass")
    test_name = "hybrid_reality_relays_payload_and_refuses_invalid_authentication"
    listed = subprocess.run([str(executable), "--list", "--ignored"], check=True,
                            capture_output=True, text=True, timeout=10)
    if f"{test_name}: test" not in listed.stdout:
        raise RuntimeError("required peer regression not registered; no skipped pass")
    scratch_root = args.scratch_root or root / "target" / "peer-tests"
    scratch_root = scratch_root.resolve()
    scratch_root.mkdir(parents=True, exist_ok=True)
    print("[2/2] REALITY/Vision payloads, invalid authentication and bidirectional DIRECT", flush=True)
    with tempfile.TemporaryDirectory(prefix="reality-", dir=scratch_root) as scratch:
        # The host filesystem is read-only. Only the disposable fixture directory
        # is writable; there is no uplink or access to the host's network namespace.
        command = ["timeout", "--kill-after=3s", "90s", "bwrap", "--unshare-user", "--unshare-net",
                   "--unshare-pid", "--die-with-parent",
                   "--ro-bind", "/", "/", "--bind", scratch, scratch,
                   "--dev", "/dev", "--proc", "/proc", "--setenv", "TMPDIR", scratch,
                   "--setenv", "MEOW_ISOLATED_PEER_TEST", "1",
                   "--setenv", "XRAY_BINARY", str(peer), str(executable),
                   "--exact", test_name, "--ignored", "--nocapture"]
        passed = False
        with subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, text=True) as process:
            for line in process.stdout:
                print(line, end="", flush=True)
                if "test result: ok. 1 passed; 0 failed; 0 ignored;" in line:
                    passed = True
            if process.wait() != 0 or not passed:
                raise RuntimeError("peer regression failed or did not execute; no skipped pass")
    print("Summary: PASS; pinned isolated peer regression completed (no host tunnel)", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Summary: FAIL; {error}", file=sys.stderr, flush=True)
        sys.exit(1)
