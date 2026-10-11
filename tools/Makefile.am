##  Makefile.am -- an automake template for Makefile.in file
##  Copyright (C) 2009 Chris Bagwell and Sane Developers.
##
##  This file is part of the "Sane" build infra-structure.  See
##  included LICENSE file for license information.

AM_CPPFLAGS += -I. -I$(srcdir) -I$(top_builddir)/include \
 -I$(top_srcdir)/include $(USB_CFLAGS)

CPPFLAGS_FOR_BUILD += -I. -I$(srcdir) -I$(top_builddir)/include \
 -I$(top_srcdir)/include $(USB_CFLAGS)

bin_PROGRAMS = sane-find-scanner gamma4scanimage
if INSTALL_UMAX_PP_TOOLS
bin_PROGRAMS += umax_pp
endif

HOTPLUG = hal/libsane.fdi hotplug/libsane.usermap hotplug-ng/libsane.db \
	  udev/libsane.rules
HOTPLUG_DIRS = hal hotplug hotplug-ng udev
HOTPLUG_DIR = dirs

bin_SCRIPTS = sane-config
noinst_SCRIPTS = $(HOTPLUG)
BUILT_SOURCES = $(HOTPLUG_DIR)
CLEANFILES = $(bin_SCRIPTS) $(dist_noinst_SCRIPTS) $(HOTPLUG) \
	     sane-desc$(BUILD_EXEEXT)

EXTRA_DIST = check-po.awk libtool-get-dll-ext mustek600iin-off.c \
	     RenSaneDlls.cmd README xerox
EXTRA_DIST += style-check.sh
EXTRA_DIST += create-changelog.sh
EXTRA_DIST += update-upstreams.sh
EXTRA_DIST += epson2usb.pl
EXTRA_DIST += junit-from-trs.sh

sane_find_scanner_SOURCES = sane-find-scanner.c
if have_usblib
sane_find_scanner_SOURCES += check-usb-chip.c
endif
sane_find_scanner_LDADD = ../sanei/libsanei.la ../lib/liblib.la \
                          $(USB_LIBS) $(IEEE1284_LIBS) $(SCSI_LIBS) $(XML_LIBS) \
			  ../backend/sane_strstatus.lo

gamma4scanimage_SOURCES = gamma4scanimage.c
gamma4scanimage_LDADD = $(MATH_LIB)

umax_pp_SOURCES  = umax_pp.c
umax_pp_SOURCES += ../backend/umax_pp_low.c
umax_pp_LDADD = ../sanei/libsanei.la ../lib/liblib.la $(MATH_LIB)

sane-desc$(BUILD_EXEEXT): sane-desc.c ../sanei/sanei_config.c ../sanei/sanei_init_debug.c ../sanei/sanei_constrain_value.c
	@rm -f sane-desc$(BUILD_EXEEXT)
	$(AM_V_CC)$(CC_FOR_BUILD) $(CPPFLAGS_FOR_BUILD) $(CFLAGS_FOR_BUILD) $(LDFLAGS_FOR_BUILD) -o $@ $^

all-local: sane-desc$(BUILD_EXEEXT)

EXTRA_DIST += sane-desc.c
EXTRA_DIST += hotplug/README hotplug/libusbscanner
EXTRA_DIST += hotplug-ng/README hotplug-ng/libsane.hotplug
EXTRA_DIST += openbsd/attach openbsd/detach

pkgconfigdir = @libdir@/pkgconfig
pkgconfig_DATA = sane-backends.pc

# When build directory is not same as source directory then any
# subdirectories that targets use must be manually created (under
# the build directory that is).
dirs:
	for subdir in $(HOTPLUG_DIRS); do \
	  $(MKDIR_P) $$subdir || exit 1; \
	  done

descriptions = ${top_srcdir}/doc/descriptions/*.desc ${top_srcdir}/doc/descriptions-external/*.desc

hotplug/libsane.usermap: sane-desc$(BUILD_EXEEXT) $(descriptions)
	@./sane-desc$(BUILD_EXEEXT) -m usermap -s ${top_srcdir}/doc/descriptions:${top_srcdir}/doc/descriptions-external \
	   -d 1 > $@

hotplug-ng/libsane.db: sane-desc$(BUILD_EXEEXT) $(descriptions)
	@./sane-desc$(BUILD_EXEEXT) -m db -s ${top_srcdir}/doc/descriptions:${top_srcdir}/doc/descriptions-external \
	   -d 0 > $@

udev/libsane.rules: sane-desc$(BUILD_EXEEXT) $(descriptions)
	@./sane-desc$(BUILD_EXEEXT) -m udev -s ${top_srcdir}/doc/descriptions:${top_srcdir}/doc/descriptions-external \
	   -d 0 > $@

hal/libsane.fdi: sane-desc$(BUILD_EXEEXT) $(descriptions)
	@./sane-desc$(BUILD_EXEEXT) -m hal -s ${top_srcdir}/doc/descriptions:${top_srcdir}/doc/descriptions-external \
	   -d 0 > $@

EXTRA_DIST += scansnap/README.md scansnap/scansnap_discover.py \
              scansnap/scansnap_session.py scansnap/scansnap_scan.py
