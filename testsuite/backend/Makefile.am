##  Makefile.am -- an automake template for Makefile.in file
##  Copyright (C) 2019  Sane Developers.
##
##  This file is part of the "Sane" build infra-structure.  See
##  included LICENSE file for license information.

SUBDIRS = scansnap

if WITH_GENESYS_TESTS
SUBDIRS += genesys
endif

if have_libavahi
if have_libcurl
if have_libxml2
check_PROGRAMS = escl_test
TESTS = $(check_PROGRAMS)

escl_test_SOURCES = escl_test.c
escl_test_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir) -I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	$(JPEG_CFLAGS) $(PNG_CFLAGS) $(TIFF_CFLAGS) $(POPPLER_GLIB_CFLAGS) \
	$(XML_CFLAGS) $(libcurl_CFLAGS) $(AVAHI_CFLAGS) -DBACKEND_NAME=escl
escl_test_LDADD = ../../backend/libescl.la \
	$(MATH_LIB) $(libcurl_LIBS) $(XML_LIBS) $(PNG_LIBS) $(JPEG_LIBS) $(TIFF_LIBS) \
	$(POPPLER_GLIB_LIBS) $(SANEI_THREAD_LIBS)
endif
endif
endif
