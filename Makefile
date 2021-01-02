#
CC=			cc
FLAGS=			-Wall -Werror -ansi -pedantic -std=c11 -I. -Iopenbsd # -DUSE_COMPAT
CFLAGS=			$(FLAGS) -g
SRCS=			main.c rip.c lib.c openbsd/sys.c compat.c
OBJS=			main.o rip.o lib.o openbsd/sys.o compat.o
PROG=			44ripd
PROGS=			$(PROG) amprroute uptunnel
TESTS=			testbitvec testipmapfind testipmapnearest \
			testisvalidnetmask testnetmask2cidr testrevbits
DTESTS=			testipmapinsert
TOBJS=			lib.o openbsd/sys.o compat.o testlib.o
LIBS=

all:			$(PROGS)

$(PROG):		$(OBJS)
			$(CC) -o $(PROG) $(OBJS) $(LIBS)

fast$(PROG):		$(SRCS) dat.h fns.h Makefile
			$(CC) $(FLAGS) -Ofast -o fast$(PROG) $(SRCS)

amprroute:		$(OBJS) amprroute.o
			$(CC) -o amprroute amprroute.o lib.o openbsd/sys.o

uptunnel:		$(OBJS) uptunnel.o
			$(CC) -o uptunnel uptunnel.o lib.o openbsd/sys.o

$(OBJS):		dat.h fns.h openbsd/stdalign.h Makefile

.c.o:
			$(CC) $(CFLAGS) -c -o $@ $<

clean:
			rm -f $(PROGS) fast$(PROG) $(TESTS) $(DTESTS) openbsd/sys.o *.o

tests:			$(TESTS) $(DTESTS)
			for t in $(TESTS); do ./$$t; done
			./testipmapinsert < testdata/testipmapinsert.data
			./testipmapinsert < testdata/testipmapinsert.data2
			./testipmapinsert < testdata/testipmapinsert.data3

$(TOBJS):		dat.h fns.h testfns.h openbsd/stdalign.h Makefile

testbitvec:		testbitvec.o $(TOBJS)
			$(CC) -o testbitvec testbitvec.o $(TOBJS)

testipmapfind:		testipmapfind.o $(TOBJS)
			$(CC) -o testipmapfind testipmapfind.o $(TOBJS)

testipmapinsert:	testipmapinsert.o $(TOBJS)
			$(CC) -o testipmapinsert testipmapinsert.o $(TOBJS)

testipmapnearest:	testipmapnearest.o $(TOBJS)
			$(CC) -o testipmapnearest testipmapnearest.o $(TOBJS)

testisvalidnetmask:	testisvalidnetmask.o $(TOBJS)
			$(CC) -o testisvalidnetmask testisvalidnetmask.o $(TOBJS)

testnetmask2cidr:	testnetmask2cidr.o $(TOBJS)
			$(CC) -o testnetmask2cidr testnetmask2cidr.o $(TOBJS)

testrevbits:		testrevbits.o $(TOBJS)
			$(CC) -o testrevbits testrevbits.o $(TOBJS)
