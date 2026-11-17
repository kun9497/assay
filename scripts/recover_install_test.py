#!/usr/bin/env python3
import runpy
import socket
import subprocess
import unittest
from pathlib import Path
from unittest import mock

download = runpy.run_path(str(Path(__file__).with_name("recover-install.py")))["download"]
asset = "https://github.com/kun9497/assay/releases/download/v1.0.0/file"
cdn = "release-assets.githubusercontent.com"


def result(code, host=cdn):
    return subprocess.CompletedProcess([], code, f"https://{host}/asset?private=signed".encode())


class RecoveryTest(unittest.TestCase):
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
