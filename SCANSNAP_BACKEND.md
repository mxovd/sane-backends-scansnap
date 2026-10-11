# ScanSnap iX1300 SANE backend

This tree contains an early `scansnap` SANE backend for the ScanSnap iX1300.
It uses the scanner's local Wi-Fi protocol and does not depend on ScanSnap
Cloud.

Implemented and validated at the protocol level:

- targeted Wi-Fi discovery and session reservation
- ADF and return/card feed paths
- simplex and duplex acquisition
- multi-sheet ADF jobs (the job stays open until the hopper is empty)
- 300 dpi color JPEG transport
- scanner-side automatic document length and cropping
- conversion to standard SANE RGB frames

The backend exports two logical devices so applications which normalize source
names, including NAPS2, can still select the physical feed path:

```text
scansnap:net:192.168.0.145:adf
scansnap:net:192.168.0.145:return
```

## Build on Arch Linux

Install the build dependencies:

```sh
sudo pacman -S --needed base-devel autoconf-archive libjpeg-turbo sane
```

From this directory, configure a build containing only this backend:

```sh
./autogen.sh BACKENDS=scansnap --prefix=/usr --sysconfdir=/etc
make -j"$(nproc)"
```

The backend shared object is written to `backend/.libs`. It can be tested
without modifying the system installation:

```sh
mkdir -p /tmp/scansnap-sane-test/dll.d
printf '%s\n' scansnap > /tmp/scansnap-sane-test/dll.conf
printf '%s\n' 'net 192.168.0.145' > /tmp/scansnap-sane-test/scansnap.conf
SANE_CONFIG_DIR=/tmp/scansnap-sane-test \
LD_LIBRARY_PATH="$PWD/backend/.libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
scanimage -L
```

The expected devices are:

```text
device `scansnap:net:192.168.0.145:adf' is a PFU ScanSnap iX1300 ADF sheetfed scanner
device `scansnap:net:192.168.0.145:return' is a PFU ScanSnap iX1300 Return Path sheetfed scanner
```

The actual loadable backend is
`backend/.libs/libsane-scansnap.so.1.4.0`. The adjacent `.so` and `.so.1`
files are symbolic links. The `.la`, `.a`, and `.o` files are build products
and are not required at runtime.

The backend implementation is split between:

- `backend/scansnap.c`: SANE API, devices, options, JPEG decoding, and page streaming
- `backend/scansnap-protocol.c` and `.h`: discovery, sessions, commands, and image transport
- `backend/scansnap.conf.in`: installed configuration template
- `backend/Makefile.am`, `configure.ac`, and `acinclude.m4`: build integration
- `doc/sane-scansnap.man`: manual page source

For a staged installation that can be reviewed or packaged without modifying
the system:

```sh
make DESTDIR="$PWD/stage" install
```

A system package should install only the `libsane-scansnap` module, its man
page, `/etc/sane.d/scansnap.conf`, and a `dll.d` entry containing `scansnap`.
Set the scanner's stable address in `scansnap.conf`:

```text
net 192.168.0.145
```

For a direct local installation on Arch Linux, copy the versioned module and
create its loader links:

```sh
sudo install -Dm755 backend/.libs/libsane-scansnap.so.1.4.0 \
  /usr/lib/sane/libsane-scansnap.so.1.4.0
sudo ln -sfn libsane-scansnap.so.1.4.0 /usr/lib/sane/libsane-scansnap.so.1
sudo ln -sfn libsane-scansnap.so.1.4.0 /usr/lib/sane/libsane-scansnap.so
printf '%s\n' scansnap | sudo tee /etc/sane.d/dll.d/scansnap >/dev/null
printf '%s\n' 'net 192.168.0.145' | sudo tee /etc/sane.d/scansnap.conf >/dev/null
```

These files are independent of the Arch `sane` package and can be removed to
uninstall this local backend.

Verify enumeration:

```sh
SANE_DEBUG_SCANSNAP=3 scanimage -L
scanimage -d 'scansnap:net:192.168.0.145:adf' --help
```

Test a simplex ADF scan:

```sh
scanimage -d 'scansnap:net:192.168.0.145:adf' \
  --source 'ADF Front' --format=png > page.png
```

The native NAPS2 package can load system SANE backends. Its Flatpak package
cannot normally load a backend installed on the host.

## NAPS2

Before installing the backend system-wide, launch the native NAPS2 build from
this source tree with the same test environment used by `scanimage`:

```sh
SANE_CONFIG_DIR=/tmp/scansnap-sane-test \
LD_LIBRARY_PATH="$PWD/backend/.libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
naps2
```

In NAPS2, create a profile using **SANE Driver**. Choose **PFU ScanSnap iX1300
ADF** for ordinary sheets or **PFU ScanSnap iX1300 Return Path** for the card
slot. Choose **Feeder** for simplex or **Duplex** for both sides, with **Color**
and **300 dpi**. Once installed system-wide, start NAPS2 normally without the
environment variables.

Device discovery can also be checked from the command line:

```sh
naps2 console --listdevices --driver sane
```

## Current limits

Only the iX1300 Wi-Fi transport, 300 dpi, and color mode are implemented.
USB, encrypted protocol mode, grayscale, monochrome, and additional resolutions
still need protocol validation. Deskew, OCR, page editing, and PDF creation are
left to the frontend. The scanner's automatic document sizing and cropping are
enabled for every scan.
