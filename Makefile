FLAGS += -g -Wall -pedantic -fPIC $(FLAGS_ADD)
CFLAGS   += $(FLAGS) -std=gnu99 -Dinline='inline __attribute__ ((gnu_inline))' $(CFLAGS_ADD)

PREFIX ?= /usr
PKGDST = $(DESTDIR)$(PREFIX)

TARGETS = flowcalc $(shell ls *.c | sed -re '/^flowcalc.c/d' -e 's;.c;.so;g')

default: all
all: $(TARGETS)

###
lpi/libprotoident.h:
	./lpi/gen-libprotoident-h.sh

lpi.so: lpi/libprotoident.h lpi.c
	$(CC) $(CFLAGS) -lflowcalc -lpjf -lprotoident -shared -o lpi.so lpi.c

ndpi.so: ndpi.c
	$(CC) $(CFLAGS) -lflowcalc -lpjf -lndpi -shared -o ndpi.so ndpi.c

%.so: %.c
	$(CC) $(CFLAGS) -lflowcalc -lpjf -shared -o $@ $<

###

flowcalc: flowcalc.c
	gcc $(CFLAGS) -lflowcalc -lpjf -ldl flowcalc.c -o flowcalc

###

install:
	install -m 755 flowcalc $(PKGDST)/bin

.PHONY: clean
clean:
	-rm -f *.o $(TARGETS)
