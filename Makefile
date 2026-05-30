CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Iinclude -fPIE
LDFLAGS = -Wl,-z,relro,-z,now -pie
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

TARGET = cproxy
SRCS = src/main.c src/util.c src/cmd.c src/cgroup.c src/iptables.c src/args.c src/proc.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

debug: CFLAGS += -g -O0 -DDEBUG
debug: clean all

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TARGET)
	./test.sh

e2e: $(TARGET)
	./e2e_test.sh

install: $(TARGET)
	install -D -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

clean:
	rm -f $(TARGET) src/*.o

.PHONY: all clean install uninstall
