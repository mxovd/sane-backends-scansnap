# ScanSnap iX1300 backend roadmap

## Project state

The `scansnap` backend is an experimental SANE backend for the PFU/Ricoh
ScanSnap iX1300. It communicates directly with the scanner over its local
Wi-Fi protocol and does not use ScanSnap Cloud.

The development branch is `scansnap-ix1300`. The GitHub repository is the
`origin` remote and the official SANE GitLab repository is the `upstream`
remote.

Validated with real hardware:

- targeted UDP discovery and device identity decoding
- scanner reservation, inquiry, hardware status, and release
- ADF simplex
- ADF duplex with each side delivered as a separate SANE page
- return/card path simplex and duplex
- 300 dpi color JPEG transport and RGB decoding
- scanner-side automatic document length and cropping
- enumeration as separate ADF and Return Path logical devices
- complete PNG output through `scanimage`
- front and back pages with independently cropped dimensions

The logical SANE devices are:

```text
scansnap:net:SCANNER_IP:adf
scansnap:net:SCANNER_IP:return
```

The repository now contains 23 Python protocol tests and 23 offline C replay
cases, together with the Python protocol-development tools.

## Current implementation

Production sources:

- `backend/scansnap.c`: SANE interface, options, JPEG decoding, and page delivery
- `backend/scansnap-protocol.c`: network discovery, sessions, commands, and image transport
- `backend/scansnap-protocol.h`: protocol types and public functions
- `backend/scansnap.conf.in`: installed configuration template
- `doc/sane-scansnap.man`: backend manual page

Build integration:

- `backend/Makefile.am`
- `backend/dll.conf.in`
- `configure.ac`
- `acinclude.m4`
- `doc/Makefile.am`
- `doc/sane.man`

The runtime module is generated at:

```text
backend/.libs/libsane-scansnap.so.1.4.0
```

The `.so` and `.so.1` files are symbolic links. Static archives, libtool files,
and object files are not required at runtime.

## Known limitations

- Wi-Fi only; USB is not implemented.
- The scanner address must be configured explicitly.
- Only 300 dpi color scanning is implemented.
- Grayscale and monochrome are not implemented.
- Scanner-side deskew and automatic orientation are not exposed.
- Encrypted or password-protected sessions are not implemented.
- Acquisition and decoding run synchronously inside `sane_start()`; NAPS2 cancellation has been tested successfully, but transport-level interruption behavior still needs implementation review.
- Both duplex sides are held in memory until delivered.
- Error recovery after disconnects and timeouts needs broader testing.

## Immediate milestone: reliable NAPS2 operation

Validated by the user with the native NAPS2 package:

- ADF simplex
- ADF duplex
- Return Path simplex
- Return Path duplex
- multiple sheets in the ADF (tested up to two sheets)
- PDF creation and correct page ordering
- repeated scans without restarting NAPS2
- cancellation during acquisition
- empty feeder reporting
- scanner-busy handling from a second NAPS2 instance (`The selected scanner is busy`)

The NAPS2 validation milestone is complete.
- network disconnect and reconnect — NAPS2 reported the scanner offline; after the scanner reconnected and its indicator became solid, scanning worked without restarting NAPS2

The backend deliberately exports Return Path as a separate logical device.
This works around frontends that normalize every scanner source to generic
`feeder` and `duplex` names.

## Repository and test infrastructure

Implemented:

- Python tools in `tools/scansnap/`
- Python tests, C replay tests, and sanitized status/capability fixtures in
  `testsuite/backend/scansnap/`
- both suites integrated into `make check` and source distributions
- GitHub Actions in `.github/workflows/scansnap.yml` for a ScanSnap-only build,
  complete configured SANE tree build, Python and C tests, `make check`,
  whitespace checks, and AddressSanitizer/UndefinedBehaviorSanitizer builds

Local validation: all 23 Python tests and 23 C replay cases pass, including
C with ASan/UBSan (leak detection disabled because the local sandbox runs under
tracing). Clean bootstrap and full-tree `make check` still need a run in CI or
an environment with `autoconf-archive`; that dependency is absent locally.
CI enables leak detection. See `testsuite/backend/scansnap/README.md` for
commands, fixture provenance, coverage and remaining hardware-test limits.

Do not commit APKs, decompiled application files, scanner output images,
personal documents, packet captures containing private data, or generated
build products.

## Packaging milestone

Add `packaging/arch/PKGBUILD` and produce an Arch package such as
`sane-scansnap-git`. It should install only:

```text
/usr/lib/sane/libsane-scansnap.so.1.4.0
/usr/lib/sane/libsane-scansnap.so.1
/usr/lib/sane/libsane-scansnap.so
/etc/sane.d/scansnap.conf
/etc/sane.d/dll.d/scansnap
/usr/share/man/man5/sane-scansnap.5
```

The package must depend on the matching SANE ABI and libjpeg. It should make
installation, upgrade, and removal reversible through `pacman`.

## Wi-Fi reliability milestone

Before adding many scan options:

1. Make network acquisition cancellable.
2. Recover cleanly from timeouts, partial replies, and disconnects.
3. Verify repeated and multi-sheet scans.
4. Improve scanner-busy, no-paper, cover-open, and device-error reporting.
5. Test concurrent processes and multiple configured scanners.
6. Add broadcast discovery so DHCP reservations are optional.
7. Reduce peak memory use by decoding or delivering pages incrementally.
8. Validate maximum page and long-document sizes.
9. Investigate encrypted and password-protected sessions.

## Scan feature milestone

Reverse, implement, and validate features individually in this order:

1. 200 and 600 dpi
2. grayscale
3. monochrome
4. scanner-side deskew
5. automatic orientation
6. blank-page detection
7. multifeed detection and reporting
8. long-document mode
9. JPEG passthrough if SANE frontends, especially NAPS2, handle it correctly

Automatic cropping already works. Frontend processing in NAPS2 can cover some
features until their scanner-side protocol fields are understood.

## USB milestone

Keep scanner commands independent from their transport:

```text
scan command layer
|-- Wi-Fi transport
`-- USB transport
```

USB work requires identifying the iX1300 USB IDs, capturing or tracing its
transfers, comparing them with the SCSI-like commands used over Wi-Fi, and
implementing the transport with SANE USB helpers or libusb. Scan parameters,
status parsing, and page delivery should be shared with the Wi-Fi path.

## Optional scan-to-SMB service

SANE is client-initiated. A workflow that reacts to the scanner button and
writes a PDF to SMB should be a separate companion service rather than part of
the backend:

```text
scansnapd
|-- monitor scanner status or button events
|-- start a scan through SANE
|-- create and optionally OCR a PDF
`-- write the result to an SMB destination
```

The service should reuse the installed SANE backend so desktop and automated
workflows use the same driver.

## Upstream preparation

Before opening a merge request against SANE on GitLab:

- follow the SANE project coding style
- build the complete SANE tree
- run the complete test suite
- add C-level protocol and error-path tests
- document the clean-room reverse-engineering process
- retain `GPL-2.0-or-later WITH SANE-exception` SPDX headers
- split large development commits into reviewable commits if requested
- keep GitHub/AUR packaging out of the upstream patch series

GitHub remains the everyday development remote. When ready, push the same
branch to a personal GitLab fork and open the upstream merge request there.

## Suggested releases

```text
v0.1  Reliable Wi-Fi scanning through NAPS2 and an Arch package
v0.2  Additional resolutions and color modes
v0.3  Discovery, cancellation, recovery, and processing options
v0.4  USB support
v1.0  Upstream-ready backend
```

The next concrete work is to confirm the new CI build matrix, then add the
Arch package described above. Open-cover hardware validation and review of
transport-level cancellation remain reliability follow-ups; the successful
NAPS2 busy and reconnect checks do not need to be repeated as prerequisites.
