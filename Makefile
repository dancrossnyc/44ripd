#
#CC=			egcc
FLAGS=			-Wall -Werror -ansi -pedantic -std=c11 -I. -DUSE_COMPAT
CFLAGS=			$(FLAGS) -g
# -O2
SRCS=			main.c rip.c lib.c log.c freebsd/sys.c compat.c
OBJS=			main.o rip.o lib.o log.o freebsd/sys.o compat.o
PROG=			44ripd
TESTS=			testbitvec testipmapfind testipmapnearest \
			testisvalidnetmask testnetmask2cidr testrevbits
DTESTS=			testipmapinsert
TOBJS=			lib.o freebsd/sys.o compat.o
LIBS=		

all:			$(PROG)

$(PROG):		$(OBJS)
			$(CC) -o $(PROG) $(OBJS) $(LIBS)

fast$(PROG):		$(SRCS) dat.h sys.h rip.h lib.h log.h
			$(CC) $(FLAGS) -Ofast -fwhole-program -flto -o fast$(PROG) $(SRCS)

tests:			$(TESTS) $(DTESTS)
			for t in $(TESTS); do ./$$t; done
			./testipmapinsert < testdata/testipmapinsert.data
			./testipmapinsert < testdata/testipmapinsert.data2
			./testipmapinsert < testdata/testipmapinsert.data3

.c.o:
			$(CC) $(CFLAGS) -c -o $@ $<

clean:
			rm -f $(PROG) fast$(PROG) $(OBJS) test*.o $(TESTS) $(DTESTS)

testbitvec:		testbitvec.o $(TOBJS) dat.h lib.h
			$(CC) -o testbitvec testbitvec.o $(TOBJS)

testipmapfind:		testipmapfind.o $(TOBJS) dat.h lib.h
			$(CC) -o testipmapfind testipmapfind.o $(TOBJS)

testipmapinsert:	testipmapinsert.o $(TOBJS) dat.h lib.h
			$(CC) -o testipmapinsert testipmapinsert.o $(TOBJS)

testipmapnearest:	testipmapnearest.o $(TOBJS) dat.h lib.h
			$(CC) -o testipmapnearest testipmapnearest.o $(TOBJS)

testisvalidnetmask:	testisvalidnetmask.o $(TOBJS) dat.h lib.h
			$(CC) -o testisvalidnetmask testisvalidnetmask.o $(TOBJS)

testnetmask2cidr:	testnetmask2cidr.o $(TOBJS) dat.h lib.h
			$(CC) -o testnetmask2cidr testnetmask2cidr.o $(TOBJS)

testrevbits:		testrevbits.o $(TOBJS) dat.h lib.h
			$(CC) -o testrevbits testrevbits.o $(TOBJS)
