CFLAGS = -std=c99 -Wall -Wextra -pedantic -pthread -g
SRC = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(filter %.c,$(SRC)))
OUTPUT = ftcp

all: $(OBJS)
	$(CC) $(CFLAGS) -o $(OUTPUT) $(OBJS)

.PHONY: clean
clean:
	rm -f *.o $(OUTPUT)
