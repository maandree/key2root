PREFIX    = /usr
MANPREFIX = $(PREFIX)/share/man

KEYPATH = /etc/key2root

CC = c99

CPPFLAGS      = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -D'KEYPATH="$(KEYPATH)"'
CFLAGS        = -Wall -O2
LDFLAGS       =
LDFLAGS_CRYPT = $(LDFLAGS) -lar2simplified -lar2 -lblake -pthread
LDFLAGS_SU    = $(LDFLAGS_CRYPT) -lenv
