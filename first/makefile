# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -g

# Source files
SRCS = main.c tcp_client.c udp_client.c

# Object files
OBJS = $(SRCS:.c=.o)

# Header files
HDRS = tcp_client.h udp_client.h

# Target executable
TARGET = ipkcpc

# Default target
all: $(TARGET)

# Link object files to create executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Compile source files into object files
%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean up object files and executable
clean:
	rm -f $(OBJS) $(TARGET)
