# Offline ScanSnap protocol tests

From the repository root, run the 23 Python tests without configuring SANE:

```sh
python3 -m unittest discover -s testsuite/backend/scansnap -p 'test_scansnap_*.py' -v
```

After the normal `./autogen.sh`, `./configure` and build, run both suites with
`make check`, or just these suites with:

```sh
make -C testsuite/backend/scansnap check VERBOSE=1
```

Out-of-tree builds are supported. The C test compiles the production
`scansnap-protocol.c` into its test translation unit, replacing only stream
`send`/`recv` with an in-memory replay. Short reads and writes force fragmented
I/O, and exhausted input models disconnection. No sockets or hardware are
needed. It checks hardware-status decoding and
request bytes, malformed framing, truncated replies, command rejection,
cover-open/no-paper results, all four feed/duplex parameter combinations,
JPEG block assembly, duplex page numbering, hopper-empty sense handling,
and cleanup after a front or back image failure. Replays return immediately when input is exhausted. Checks remain enabled with `NDEBUG`.

The Python tests are skipped by Automake if Python 3 is unavailable; CI runs
Python explicitly so a missing interpreter cannot silently skip coverage.
GitHub Actions builds the ScanSnap-only configuration, the complete configured
SANE tree, and ScanSnap with AddressSanitizer and UndefinedBehaviorSanitizer.
All three run `make check`.

## Fixture provenance and limits

`fixtures/hardware_{idle,adf,return}.hex` and `fixtures/vpd.hex` are the
recorded payload bytes previously embedded in the Python session tests.
They contain generic iX1300 status/capability fields, with no IP addresses,
MAC addresses, serial numbers, host names or image content. The C replay
wraps the hardware payloads in synthetic command-reply headers. The Python
suite also decodes the VPD payload. Other replies, errors and JPEG marker
sequences are synthetic and are not represented as hardware captures.

No actual JPEG document is included. These tests check transport assembly,
not JPEG decoding or live timing. Discovery/reservation sockets and real
cancellation, reconnect behavior and frontend integration still require
additional tests; offline replay does not replace hardware validation.
