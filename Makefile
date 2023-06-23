.POSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)

BIN = key2root key2root-lskeys key2root-addkey key2root-rmkey key2root-crypt

HDR = arg.h crypt.h

MAN8 = $(BIN:=.8)
OBJ = $(BIN:=.o) crypt.o

all: $(BIN)
$(OBJ): $(HDR)

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

key2root: key2root.o crypt.o
	$(CC) -o $@ $@.o crypt.o $(LDFLAGS_CRYPT)

key2root-lskeys: key2root-lskeys.o
	$(CC) -o $@ $@.o $(LDFLAGS)

key2root-addkey: key2root-addkey.o crypt.o
	$(CC) -o $@ $@.o crypt.o $(LDFLAGS_CRYPT)

key2root-rmkey: key2root-rmkey.o
	$(CC) -o $@ $@.o $(LDFLAGS)

key2root-crypt: key2root-crypt.o crypt.o
	$(CC) -o $@ $@.o crypt.o $(LDFLAGS_CRYPT)

check: key2root-crypt
	+@$(MAKE) -f .pepper-validation.mk check ## DO NOT REMOVE

install: $(BIN)
	mkdir -p -- "$(DESTDIR)$(PREFIX)/bin"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man8/"
	cp -- $(BIN) "$(DESTDIR)$(PREFIX)/bin/"
	cd -- "$(DESTDIR)$(PREFIX)/bin/" && chmod -- 4755 key2root
	cp -- $(MAN8) "$(DESTDIR)$(MANPREFIX)/man8/"

uninstall:
	-cd -- "$(DESTDIR)$(PREFIX)/bin/" && rm -f -- $(BIND)
	-cd -- "$(DESTDIR)$(MANPREFIX)/man8/" && rm -f -- $(MAN8)

clean:
	-rm -f -- *.o *.a *.lo *.su *.so *.so.* *.gch *.gcov *.gcno *.gcda
	-rm -f -- $(BIN)

.SUFFIXES:
.SUFFIXES: .o .c

.PHONY: all check install uninstall clean
