#!/usr/bin/env python3
"""Install from a commit-pinned checkout when GitHub's normal CDN path fails."""
import argparse
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
RELEASES = "https://github.com/kun9497/assay/releases/download"
TRANSIENT = {5, 6, 7, 16, 18, 28, 35, 52, 55, 56, 92}


def download(curl, url, path):
    # Ignore per-user curlrc options. HTTPS, certificate checks, redirects and
    # the operator's normal proxy settings apply on every attempt.
    cmd = [curl, "--disable", "--proto", "=https", "--proto-redir", "=https",
           "--silent", "--show-error", "--fail", "--location", "--connect-timeout",
           "5", "--speed-limit", "1", "--speed-time", "20", "--output", str(path),
           "--write-out", "%{url_effective}"]
    first = subprocess.run(cmd + [url], stdout=subprocess.PIPE)
    if first.returncode == 0:
        return
    # A signed redirect URL is private and short-lived. Keep only its hostname.
    host = urlsplit(first.stdout.decode("ascii")).hostname
    if first.returncode not in TRANSIENT or not host or not (
            host == "github.com" or host.endswith(".githubusercontent.com")):
        raise SystemExit(first.returncode)
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as err:
        raise SystemExit(f"Cannot resolve {host}: {err}") from err
    for address in dict.fromkeys(info[4][0] for info in addresses):
        ip = f"[{address}]" if ":" in address else address
        print(f"Retrying {host} at DNS address {address}", file=sys.stderr)
        # Only the connection address changes. curl retains the URL hostname for
        # SNI and certificate verification. Start again at the public asset URL.
        retry = subprocess.run(cmd + ["--resolve", f"{host}:443:{ip}", url],
                               stdout=subprocess.DEVNULL)
        if retry.returncode == 0:
            return
        if retry.returncode not in TRANSIENT:
            raise SystemExit(retry.returncode)
    raise SystemExit(f"All DNS addresses for {host} failed; check the network or proxy.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-b", "--bin-dir", help="installation directory")
    opts = parser.parse_args()
    os_name = platform.system().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64",
            "aarch64": "arm64"}.get(platform.machine().lower())
    if os_name not in {"linux", "darwin", "windows"} or not arch:
        raise SystemExit("No prebuilt release for this operating system and architecture")
    if os_name == "windows":
        installer = ROOT / "install.ps1"
        version_line = r"^\$DefaultVersion = '(v[0-9]+\.[0-9]+\.[0-9]+)'$"
    else:
        installer = ROOT / "install.sh"
        version_line = r'^VERSION="(v[0-9]+\.[0-9]+\.[0-9]+)"$'
    default = re.search(version_line, installer.read_text(encoding="utf-8"), re.MULTILINE)
    if not default:
        raise SystemExit(f"The pinned {installer.name} has no release version")
    version = default.group(1)
    curl = shutil.which("curl.exe" if os_name == "windows" else "curl")
    if not curl:
        raise SystemExit("The recovery installer needs curl")
    extension = "zip" if os_name == "windows" else "tar.gz"
    archive = f"assay_{version[1:]}_{os_name}_{arch}.{extension}"
    sums = f"assay_{version[1:]}_checksums.txt"
    with tempfile.TemporaryDirectory(prefix="assay-release-") as bundle:
        for name in (archive, sums, sums + ".sig"):
            download(curl, f"{RELEASES}/{version}/{name}", Path(bundle) / name)
        env = dict(os.environ, ASSAY_RELEASE_DIR=bundle, ASSAY_ARCH=arch)
        env.pop("ASSAY_ALLOW_UNSIGNED", None)
        if os_name == "windows":
            shell = shutil.which("pwsh") or "powershell.exe"
            cmd = [shell, "-NoProfile", "-File", str(installer), "-Version", version]
            if opts.bin_dir:
                cmd += ["-BinDir", opts.bin_dir]
        else:
            env["ASSAY_OS"] = os_name
            cmd = ["sh", str(installer)]
            if opts.bin_dir:
                cmd += ["-b", opts.bin_dir]
            cmd.append(version)
        return subprocess.run(cmd, env=env).returncode


if __name__ == "__main__":
    sys.exit(main())
