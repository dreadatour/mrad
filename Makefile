BINDIR ?= /usr/local/bin
LINUX_COMPILER = gcc

MRAD_SOURCES = mrad.c mrim.c socket.c

all:	release

install:
	install mrad ${BINDIR}/mrad

uninstall:
	rm -f ${BINDIR}/mrad

clean:
	rm -f mrad

mrad:	${MRAD_SOURCES}
	${LINUX_COMPILER} -I. ${MRAD_SOURCES} -o mrad

release:	mrad

