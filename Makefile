# Makefile for aclrepair

CFLAGS=-g -Wall

BINS=aclrepair
OBJS=main.o acls.o argv.o

all: aclrepair

aclrepair: $(OBJS)
	$(CC) -o aclrepair $(OBJS)

main.o: main.c acls.h
acls.o: acls.c acls.h
argv.o: argv.c argv.h

clean:
	rm -f core $(BINS) *.o *~ \#

distclean: clean

push: distclean
	git add -A && git commit -a && git push
