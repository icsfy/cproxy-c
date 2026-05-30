CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2

TARGET = cproxy

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)

.PHONY: all clean