# Makefile for aclrepair

CFLAGS=-g -Wall

BINS=aclrepair
OBJS=aclrepair.o

all: aclrepair

aclrepair: $(OBJS)
	$(CC) -o aclrepair $(OBJS)

clean:
	rm -f core $(BINS) *.o *~ \#

distclean: clean

push: distclean
	git add -A && git commit -a && git push
