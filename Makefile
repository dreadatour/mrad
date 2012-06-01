BINDIR ?= /usr/local/bin
LINUX_COMPILER = gcc
CFLAGS+=-W
CFLAGS+=-Wall
CFLAGS+=-Wextra
#CFLAGS+=-Werror
CFLAGS+=-ggdb
#CFLAGS+=-I.
CFLAGS+=-DDEBUG=1

MRAD_SOURCES = mrad.c mrim.c socket.c

OBJS=$(addsuffix .o,${MRAD_SOURCES})

all:	release

install:
	install mrad ${BINDIR}/mrad

uninstall:
	rm -f ${BINDIR}/mrad

clean:
	rm -f mrad *.o

mrad:	${OBJS} Makefile
	${LINUX_COMPILER} ${CFLAGS} ${OBJS} -o mrad

%.c.o: %.c
	${LINUX_COMPILER} -c ${CFLAGS}  -o $@ $<

#.PHONY:${MRAD_SOURCES}

release:	mrad

user=$(addprefix -u,$(shell cat user))
password=$(addprefix -p,$(shell cat password))

dbg: mrad
	nemiver ./mrad ${user} ${password}

run: mrad
	./mrad ${user} ${password}

