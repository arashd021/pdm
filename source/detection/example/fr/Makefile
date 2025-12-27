CC := gcc
CFLAGS :=
LDFLAGS := -lrt

TARGETS := victim F+R

.PHONY: all clean

all: $(TARGETS)

victim: victim.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

F+R: F+R.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)
