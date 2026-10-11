# SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
check_PROGRAMS = scansnap_protocol_test
TESTS = $(check_PROGRAMS) python-tests.sh
AM_CPPFLAGS += -I$(top_builddir)/include -I$(top_srcdir)/include \
              -I$(top_srcdir)/backend
scansnap_protocol_test_SOURCES = scansnap_protocol_test.c
EXTRA_scansnap_protocol_test_SOURCES = ../../../backend/scansnap-protocol.c \
    ../../../backend/scansnap-protocol.h
TESTS_ENVIRONMENT = SCANSNAP_FIXTURES='$(srcdir)/fixtures'; export SCANSNAP_FIXTURES;
EXTRA_DIST = README.md python-tests.sh test_scansnap_discover.py \
    test_scansnap_session.py test_scansnap_scan.py \
    fixtures/hardware_idle.hex fixtures/hardware_adf.hex \
    fixtures/hardware_return.hex fixtures/vpd.hex
