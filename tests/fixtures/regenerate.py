"""How the golden fixtures were produced. Run on a machine with nmap.

These are real nmap output, not hand-written XML. That is the point: the
synthetic suite passed while the importer refused every genuine nmap file,
because hand-written fixtures omitted the `<!DOCTYPE nmaprun>` line that
real output always carries.

Start the listeners below, then run this. Only scan hosts you own; the
commands here target 127.0.0.1 and ::1 exclusively.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent

LISTENERS = """
Start these first (see tests/fixtures/listeners.py):
  2222  raw socket emitting  SSH-2.0-OpenSSH_7.4
  2525  raw socket emitting  220 mail.lab.test ESMTP Postfix (Ubuntu)
  6379  accepts and says nothing  -> nmap reports 'tcpwrapped'
  8080  http.server with server_version = Apache/2.4.49
  9999  nothing listening         -> closed
"""

SCANS = {
    "nmap_sV_localhost.xml":
        ["-sT", "-sV", "-p", "2222,2525,6379,8080,9999", "127.0.0.1"],
    "nmap_portscan_only.xml":
        ["-sT", "-p", "2222,8080,9999", "127.0.0.1"],
    "nmap_ipv6.xml":
        ["-6", "-sT", "-sV", "-p", "8080,2222", "::1"],
    "nmap_ping_only.xml":
        ["-sn", "127.0.0.1"],
    "nmap_with_scripts.xml":
        ["-sT", "-sV", "-p", "2222,8080", "--script", "banner", "127.0.0.1"],
    "nmap_host_down.xml":
        ["-sT", "-p", "80,443", "192.0.2.99", "--host-timeout", "5s"],
}


def main() -> int:
    nmap = sys.argv[1] if len(sys.argv) > 1 else "nmap"
    print(LISTENERS)
    for name, args in SCANS.items():
        out = HERE / name
        print(f"[*] {name}")
        subprocess.run([nmap, *args, "-oX", str(out)],
                       check=False, capture_output=True)
    print("[*] done; re-run pytest tests/test_golden_nmap.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
