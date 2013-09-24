CFLAGS = -O2 -Wall # -D NOBEEP

default: binaries # doc

binaries: seccure-key seccure-encrypt seccure-decrypt seccure-sign \
	seccure-verify seccure-signcrypt seccure-veridec seccure-dh

doc: seccure.1 seccure.1.html

install: default
	install -m0755 seccure-key $(DESTDIR)/usr/bin
	ln -f $(DESTDIR)/usr/bin/seccure-key $(DESTDIR)/usr/bin/seccure-encrypt
	ln -f $(DESTDIR)/usr/bin/seccure-key $(DESTDIR)/usr/bin/seccure-decrypt
	ln -f $(DESTDIR)/usr/bin/seccure-key $(DESTDIR)/usr/bin/seccure-sign
	ln -f $(DESTDIR)/usr/bin/seccure-key $(DESTDIR)/usr/bin/seccure-verify
	ln -f $(DESTDIR)/usr/bin/seccure-key $(DESTDIR)/usr/bin/seccure-signcrypt
	ln -f $(DESTDIR)/usr/bin/seccure-key $(DESTDIR)/usr/bin/seccure-veridec
	ln -f $(DESTDIR)/usr/bin/seccure-key $(DESTDIR)/usr/bin/seccure-dh
	install -m0644 seccure.1 $(DESTDIR)/usr/share/man/man1

clean:
	rm -f *.o *~ seccure-key seccure-encrypt seccure-decrypt seccure-sign \
	seccure-verify seccure-signcrypt seccure-veridec \
	seccure-dh # seccure.1 seccure.1.html

rebuild: clean default

numtheory.o: numtheory.h
ecc.o: ecc.h
curves.o: curves.h
serialize.o: serialize.h
protocol.o: protocol.h
aes256ctr.o: aes256ctr.h

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

seccure-key: seccure.o numtheory.o ecc.o serialize.o protocol.o curves.o aes256ctr.o
	$(CC) $(CFLAGS) -o seccure-key -lgcrypt $^
	strip seccure-key

seccure-encrypt: seccure-key
	ln -f seccure-key seccure-encrypt

seccure-decrypt: seccure-key
	ln -f seccure-key seccure-decrypt

seccure-sign: seccure-key
	ln -f seccure-key seccure-sign

seccure-verify: seccure-key
	ln -f seccure-key seccure-verify

seccure-signcrypt: seccure-key
	ln -f seccure-key seccure-signcrypt

seccure-veridec: seccure-key
	ln -f seccure-key seccure-veridec

seccure-dh: seccure-key
	ln -f seccure-key seccure-dh

seccure.1: seccure.manpage.xml
	xmltoman seccure.manpage.xml > seccure.1

seccure.1.html: seccure.manpage.xml
	xmlmantohtml seccure.manpage.xml > seccure.1.html
