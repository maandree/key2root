.POSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)

BIN = key2root key2root-lskeys key2root-addkey key2root-rmkey

HDR = arg.h

MAN8 = $(BIN:=.8)
OBJ = $(BIN:=.o)

all: $(BIN)
$(OBJ): $(HDR)

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

.o:
	$(CC) -o $@ $< $(LDFLAGS)

.c:
	$(CC) -o $@ $< $(CFLAGS) $(CPPFLAGS) $(LDFLAGS)

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

.PHONY: all install uninstall clean
