PREFIX    = /usr
MANPREFIX = $(PREFIX)/share/man

KEYPATH = /etc/key2root

CC = c99

COMMON_SANITIZE = -fsanitize=alignment,shift,signed-integer-overflow,object-size,null,undefined,bounds,address
CLANG_SANITIZE  = -O1 $(COMMON_SANITIZE),cfi -flto -fvisibility=hidden -fno-sanitize-trap=cfi
GCC_SANITIZE    = -O1 $(COMMON_SANITIZE)
#SANITIZE        = $(CLANG_SANITIZE)
#SANITIZE        = $(GCC_SANITIZE)

CPPFLAGS      = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -D'KEYPATH="$(KEYPATH)"'
CFLAGS        = $(SANITIZE) -Wall -O2
LDFLAGS       = $(SANITIZE)
LDFLAGS_CRYPT = $(SANITIZE) $(LDFLAGS) -lar2simplified -lar2 -lblake -pthread
LDFLAGS_SU    = $(SANITIZE) $(LDFLAGS_CRYPT) -lenv
