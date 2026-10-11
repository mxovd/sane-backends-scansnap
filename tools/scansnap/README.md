# ScanSnap protocol development tools

These Python 3 tools use only the standard library. They implement the local
Wi-Fi protocol investigated for the iX1300; they do not use ScanSnap Cloud.
Run each script with `--help` for arguments:

```sh
python3 tools/scansnap/scansnap_discover.py --help
python3 tools/scansnap/scansnap_session.py --help
python3 tools/scansnap/scansnap_scan.py --help
```

Discovery sends UDP probes; its optional hello probe reads TCP greetings.
The session probe reserves the scanner, reads inquiry and hardware status,
and releases it. The scan probe reserves the scanner and feeds a loaded
sheet, writing JPEG output. Live probes require Linux routing tools (`ip`)
and a reachable scanner; the offline test suite requires neither.

Tests live in `testsuite/backend/scansnap`. Keep real scanner identities,
packet captures, scan output, APKs and decompiled application files outside
the repository. The fixtures contain only protocol bytes and generic device
capabilities/status; synthetic discovery tests use documentation addresses
and a placeholder identity.
