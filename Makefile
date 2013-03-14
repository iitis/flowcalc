FLAGS += -g -Wall -pedantic -fPIC $(FLAGS_ADD)
CFLAGS   += $(FLAGS) -std=gnu99 -Dinline='inline __attribute__ ((gnu_inline))' $(CFLAGS_ADD)

PREFIX ?= /usr
PKGDST = $(DESTDIR)$(PREFIX)

TARGETS = flowcalc $(shell ls *.c | sed -re '/^flow(calc|dump).c/d' -e 's;\.c;.so;g') flowdump

default: all
all: $(TARGETS)

###
lpi/libprotoident.h:
	./lpi/gen-libprotoident-h.sh

lpi.so: lpi/libprotoident.h lpi.c
	$(CC) $(CFLAGS) -shared -o lpi.so lpi.c -lprotoident 

ndpi.so: ndpi.c
	$(CC) $(CFLAGS) -shared -o ndpi.so ndpi.c -lndpi

%.so: %.c
	$(CC) $(CFLAGS) -shared -o $@ $< -lflowcalc -lm -lpjf 

###

flowcalc: flowcalc.c
	gcc $(CFLAGS) flowcalc.c -o flowcalc -lflowcalc -lpjf -ldl -DMYDIR=\"$(CURDIR)\"

flowdump: flowdump.c
	gcc $(CFLAGS) flowdump.c -o flowdump -lflowcalc -lpjf 

###

install:
	install -m 755 flowcalc $(PKGDST)/bin

.PHONY: clean
clean:
	-rm -f *.o $(TARGETS)
