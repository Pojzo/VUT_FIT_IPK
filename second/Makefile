CC=gcc
SRC_FILES=main.c arg_handler.c

HEADERS=arg_handler.h

OBJ_FILES=$(SRC_FILES:.c=.o)

EXECUTABLE=ipk-sniffer

CFLAGS=-std=c99 -pedantic -Wall -Wextra -g -D_GNU_SOURCE

LDFLAGS= -lpcap

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJ_FILES)
	$(CC) $(CFLAGS) $(OBJ_FILES) -o $@ $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ_FILES) $(EXECUTABLE)
