FLAGS += -g -Wall -pedantic -fPIC $(FLAGS_ADD)
CFLAGS   += $(FLAGS) -std=gnu99 -Dinline='inline __attribute__ ((gnu_inline))' $(CFLAGS_ADD)

PREFIX ?= /usr
PKGDST = $(DESTDIR)$(PREFIX)

TARGETS = flowcalc $(shell ls *.c | sed -re '/^flowcalc.c/d' -e 's;.c;.so;g')

default: all
all: $(TARGETS)

%.so: %.c
	$(CC) $(CFLAGS) -lflowcalc -lpjf -shared -o $@ $<

flowcalc: flowcalc.c
	gcc $(CFLAGS) -lflowcalc -lpjf -ldl flowcalc.c -o flowcalc

install:
	install -m 755 flowcalc $(PKGDST)/bin

.PHONY: clean
clean:
	-rm -f *.o $(TARGETS)
