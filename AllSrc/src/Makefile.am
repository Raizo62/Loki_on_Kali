# src/Makefile.am
# Copyright 2010 Daniel Mende <dmende@ernw.de> 

instdir = $(pkgdatadir)

AM_CPPFLAGS = -fpic -I$(top_srcdir)/include @PCAPINC@ @DNETINC@

bin_SCRIPTS = @LOKI_GTK@ @LOKI_URWID@
EXTRA_SCRIPTS = 
bin_PROGRAMS = mpls_tunnel pppoe_tunnel
noinst_PROGRAMS = bf_test

mpls_tunnel_SOURCES = mpls-tunnel.c ../lib/mplstun.c
mpls_tunnel_LDADD = @DNETLIB@ @PCAPLIB@

pppoe_tunnel_SOURCES = pppoe-tunnel.c ../lib/pppoetun.c
pppoe_tunnel_LDADD = @DNETLIB@ @PCAPLIB@

bf_test_SOURCES = 	bf_test.c \
					../lib/bf.c \
					../lib/bf/ospf.c \
					../lib/bf/isis.c \
					../lib/bf/tacacs.c \
					../lib/bf/tcpmd5.c \
					../lib/bf/bfd.c \
					../lib/algos/md5.c \
					../lib/algos/hmac_md5.c \
					../lib/algos/sha1.c \
					../lib/algos/sha2.c \
					../lib/algos/hmac_sha2.c
bf_test_CFLAGS = @PTHREAD_CFLAGS@
bf_test_LDADD = @PTHREAD_LIBS@

noinst_SCRIPTS = loki-build

loki-build:
	$(SED) -i.bak 's#DATA_DIR="."#DATA_DIR="$(instdir)"#g' loki.py
	touch python-build

