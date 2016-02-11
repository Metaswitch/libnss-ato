# Makefile for libnss-ato

#### Start of system configuration section. ####

CC = gcc
INSTALL = /usr/bin/install
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

prefix = ""
exec_prefix = ${prefix}

# Where the installed binary goes.
bindir = ${exec_prefix}/bin
binprefix =

sysconfdir = /etc

# mandir = /usr/local/src/less-394/debian/less/usr/share/man
manext = 1
manprefix =

#### End of system configuration section. ####

DEB_VERSION ?= 0.2-clearwater-$(shell date +%y%m%d.%H%M%S)
DEB_COMPONENT := libnss-ato

all:	libnss_ato libnss_ato_test 

libnss_ato:	libnss_ato.c
	${CC} -fPIC -Wall -shared -o libnss_ato.so.2 -Wl,-soname,libnss_ato.so.2 libnss_ato.c

test:	libnss_ato_test.c
	${CC} -fPIC -Wall -o libnss_ato_test libnss_ato_test.c

install:	
	# remember /lib/libnss_compat.so.2 -> libnss_compat-2.3.6.so
	${INSTALL_DATA} libnss_ato.so.2 ${prefix}/lib/libnss_ato-2.3.6.so
	${INSTALL_DATA} libnss-ato.3 ${prefix}/usr/share/man/man3
	cd ${prefix}/lib && ln -fs libnss_ato-2.3.6.so libnss_ato.so.2

clean:
	rm -f libnss_ato.so.2 libnss_ato_test
	rm -rf debian/libnss-ato
	rm -f build-stamp

deb:
	@echo "${DEB_COMPONENT} (${DEB_VERSION}) unstable; urgency=low\n" >debian/changelog
	@echo "  * build from revision $$(git rev-parse HEAD)\n" >>debian/changelog
	fakeroot debian/rules binary
