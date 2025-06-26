# Makefile for aclrepair

CFLAGS=-g -Wall

BINS=aclrepair
OBJS=main.o acls.o argv.o

all: aclrepair

aclrepair: $(OBJS)
	$(CC) -o aclrepair $(OBJS)

main.o: main.c acls.h config.h
acls.o: acls.c acls.h config.h
argv.o: argv.c argv.h config.h

clean:
	rm -fr core $(BINS) *.o *~ autom4te.cache \#

distclean: clean
	rm -f config.log config.status

push: distclean
	git add -A && git commit -a && git push
