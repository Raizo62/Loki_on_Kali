# Makefile.am
# Copyright 2010 Daniel Mende <dmende@ernw.de> 

instdir = $(pkgdatadir)
SUBDIRS =	lib src modules

AUX_DIST =	install-sh

noinst_SCRIPTS = python-build

python-build:
	$(PYTHON) setup.py build
	touch python-build

python-clean:
	rm -rf *build
	rm -f py-installed-files

clean: clean-recursive python-clean

distclean: clean-recursive

python-install:
	$(PYTHON) setup.py install --prefix=$(DESTDIR)`python-config --prefix` --record py-installed-files

install-exec-local: python-install

python-uninstall:
	cat py-installed-files | xargs rm -f

uninstall-local: python-uninstall
