CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Iinclude
LDFLAGS = -Wl,-z,relro,-z,now
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

TARGET = cproxy
SRCS = src/main.c src/util.c src/cmd.c src/cgroup.c src/iptables.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	install -D -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET) src/*.o

.PHONY: all clean install uninstall
