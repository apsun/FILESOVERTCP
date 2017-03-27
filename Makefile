CFLAGS = -std=c99 -Wall -Wextra -pedantic -pthread -g
SRC = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(filter %.c,$(SRC)))
OUTPUT = ftcp

all: $(OBJS)
	$(CC) $(CFLAGS) -o $(OUTPUT) $(OBJS)

.PHONY: test
test:
	mkdir -p test
	mkdir -p state
	mkdir -p download
	dd if=/dev/urandom of=test/a.bin bs=1M count=100

.PHONY: clean
clean:
	rm -f *.o $(OUTPUT)
	rm -rf test
	rm -rf state
	rm -rf download
