PREFIX    = /usr
MANPREFIX = $(PREFIX)/share/man

KEYPATH = /etc/key2root

CC = cc

CPPFLAGS = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -D'KEYPATH="$(KEYPATH)"'
CFLAGS   = -std=c99 -Wall -O2
LDFLAGS  = -lcrypt
