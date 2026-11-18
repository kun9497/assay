#!/usr/bin/env python3
import os
import runpy
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

recovery = runpy.run_path(str(Path(__file__).with_name("recover-install.py")))
download = recovery["download"]
main = recovery["main"]
asset = "https://github.com/kun9497/assay/releases/download/v1.0.0/file"
cdn = "release-assets.githubusercontent.com"


def result(code, host=cdn):
    return subprocess.CompletedProcess([], code, f"https://{host}/asset?private=signed".encode())


class RecoveryTest(unittest.TestCase):
    def test_main_passes_a_complete_signed_bundle_to_the_platform_installer(self):
        for system, machine, arch, shell, bin_dir in (
                ("Linux", "x86_64", "amd64", "sh", None),
                ("Darwin", "aarch64", "arm64", "sh", "install here"),
                ("Windows", "AMD64", "amd64", "pwsh", "install here"),
                ("Windows", "arm64", "arm64", "powershell.exe", None)):
            with self.subTest(system=system, machine=machine), tempfile.TemporaryDirectory() as checkout:
                root = Path(checkout)
                (root / "install.sh").write_text('VERSION="v9.8.7"\n', encoding="utf-8")
                (root / "install.ps1").write_text("$DefaultVersion = 'v9.8.6'\n", encoding="utf-8")
                os_name = system.lower()
                version = "9.8.6" if system == "Windows" else "9.8.7"
                extension = "zip" if system == "Windows" else "tar.gz"
                names = [f"assay_{version}_{os_name}_{arch}.{extension}",
                         f"assay_{version}_checksums.txt", f"assay_{version}_checksums.txt.sig"]
                downloads = []

                def fetch(curl, url, path):
                    downloads.append((curl, url, path))
                    path.write_text(path.name, encoding="utf-8")

                def which(tool):
                    if tool == "pwsh" and shell != "pwsh":
                        return None
                    return f"/tools/{tool}"

                def install(cmd, *, env):
                    # Observe the bundle while main still owns it, before its
                    # TemporaryDirectory removes the downloaded assets.
                    bundle = Path(env["ASSAY_RELEASE_DIR"])
                    self.assertEqual(sorted(p.name for p in bundle.iterdir()), sorted(names))
                    self.assertEqual(env["ASSAY_ARCH"], arch)
                    self.assertEqual(env["RECOVERY_TEST_AMBIENT"], "preserved")
                    self.assertNotIn("ASSAY_ALLOW_UNSIGNED", env)
                    if system == "Windows":
                        self.assertEqual(cmd, [which("pwsh") or "powershell.exe", "-NoProfile",
                                             "-File", str(root / "install.ps1"), "-Version", "v9.8.6"]
                                         + (["-BinDir", bin_dir] if bin_dir else []))
                    else:
                        self.assertEqual(env["ASSAY_OS"], os_name)
                        self.assertEqual(cmd, ["sh", str(root / "install.sh")]
                                         + (["-b", bin_dir] if bin_dir else []) + ["v9.8.7"])
                    return subprocess.CompletedProcess(cmd, 23)

                argv = ["recover-install.py"] + (["-b", bin_dir] if bin_dir else [])
                with mock.patch.dict(main.__globals__, {"ROOT": root, "download": fetch}), \
                     mock.patch.object(sys, "argv", argv), \
                     mock.patch("platform.system", return_value=system), \
                     mock.patch("platform.machine", return_value=machine), \
                     mock.patch("shutil.which", side_effect=which), \
                     mock.patch.dict(os.environ, {"ASSAY_ALLOW_UNSIGNED": "1", "RECOVERY_TEST_AMBIENT": "preserved"}), \
                     mock.patch.object(subprocess, "run", side_effect=install) as run:
                    self.assertEqual(main(), 23)
                    # Removing the flag for the child must not alter the caller.
                    self.assertEqual(os.environ["ASSAY_ALLOW_UNSIGNED"], "1")
                run.assert_called_once()
                self.assertEqual([url for _, url, _ in downloads],
                                 [f"https://github.com/kun9497/assay/releases/download/v{version}/{name}" for name in names])
                self.assertEqual([curl for curl, _, _ in downloads],
                                 [which("curl.exe" if system == "Windows" else "curl")] * 3)
                self.assertEqual([path.name for _, _, path in downloads], names)
                self.assertEqual(len({path.parent for _, _, path in downloads}), 1)

    def test_main_does_not_install_an_incomplete_bundle(self):
        with mock.patch.object(sys, "argv", ["recover-install.py"]), \
             mock.patch("platform.system", return_value="Linux"), \
             mock.patch("platform.machine", return_value="x86_64"), \
             mock.patch("shutil.which", return_value="curl"), \
             mock.patch.dict(main.__globals__, {"download": mock.Mock(side_effect=[None, SystemExit(28)])}), \
             mock.patch.object(subprocess, "run") as run:
            with self.assertRaises(SystemExit) as err:
                main()
            self.assertEqual(err.exception.code, 28)
        run.assert_not_called()

    def test_uses_system_dns_with_the_original_https_hostname(self):
        addresses = [(0, 0, 0, "", (address, 443)) for address in ("192.0.2.1", "192.0.2.1", "2001:db8::1")]
        with mock.patch.object(socket, "getaddrinfo", return_value=addresses) as dns, \
             mock.patch.object(subprocess, "run", side_effect=[result(28), result(7), result(0)]) as run:
            download("curl", asset, "out")
        dns.assert_called_once_with(cdn, 443, type=socket.SOCK_STREAM)
        for call, address in zip(run.call_args_list[1:], ("192.0.2.1", "[2001:db8::1]")):
            args = call.args[0]
            self.assertEqual(args[-3:], ["--resolve", f"{cdn}:443:{address}", asset])
            self.assertEqual(args[args.index("--proto-redir")+1], "=https")
            self.assertNotIn("--insecure", args)

    def test_success_certificate_failures_and_foreign_hosts_do_not_retry(self):
        for code, host in ((0, cdn), (60, cdn), (22, cdn), (28, "example.org")):
            with self.subTest(code=code, host=host), mock.patch.object(socket, "getaddrinfo") as dns, \
                 mock.patch.object(subprocess, "run", return_value=result(code, host)):
                if code:
                    with self.assertRaises(SystemExit) as err:
                        download("curl", asset, "out")
                    self.assertEqual(err.exception.code, code)
                else:
                    download("curl", asset, "out")
                dns.assert_not_called()


if __name__ == "__main__":
    unittest.main()
