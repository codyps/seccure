CFLAGS ?= -O2 -Wall # -D NOBEEP

default: binaries # doc

BIN = seccure-key
BIN_SYM = seccure-encrypt seccure-decrypt seccure-sign \
	  seccure-verify seccure-signcrypt seccure-veridec seccure-dh
binaries: $(BIN) $(BIN_SYM)

doc: seccure.1 seccure.1.html

install: default
	mkdir -p $(DESTDIR)/usr/bin
	install -m0755 seccure-key $(DESTDIR)/usr/bin
	$(foreach sym,$(BIN_SYM),\
		ln -f $(DESTDIR)/usr/bin/$(BIN) $(DESTDIR)/usr/bin/$(sym);)
	mkdir -p $(DESTDIR)/usr/share/man/man1
	install -m0644 seccure.1 $(DESTDIR)/usr/share/man/man1

clean:
	rm -f *.o *~ $(BIN) $(BIN_SYM) # seccure.1 seccure.1.html

rebuild: clean default

numtheory.o: numtheory.h
ecc.o: ecc.h
curves.o: curves.h
serialize.o: serialize.h
protocol.o: protocol.h
aes256ctr.o: aes256ctr.h

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN): seccure.o numtheory.o ecc.o serialize.o protocol.o curves.o aes256ctr.o
	$(CC) $(CFLAGS) -o $@ -lgcrypt $^
	strip $@

$(BIN_SYM) : $(BIN)
	ln -f $< $@

seccure.1: seccure.manpage.xml
	xmltoman seccure.manpage.xml > seccure.1

seccure.1.html: seccure.manpage.xml
	xmlmantohtml seccure.manpage.xml > seccure.1.html
