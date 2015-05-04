AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

pkglib_LTLIBRARIES = daq_pfring.la
daq_pfring_la_SOURCES = daq_pfring.c
daq_pfring_la_CFLAGS = -DBUILDING_SO
daq_pfring_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
