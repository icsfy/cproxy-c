CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

TARGET = cproxy

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

install: $(TARGET)
	install -D -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean install uninstall