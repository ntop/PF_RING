AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

pkglib_LTLIBRARIES = daq_pfring_zc.la
daq_pfring_zc_la_SOURCES = daq_pfring_zc.c
daq_pfring_zc_la_CFLAGS = -DBUILDING_SO
daq_pfring_zc_la_LDFLAGS = -module -export-dynamic -avoid-version -shared -lrt
