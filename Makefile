CFLAGS = -O2 # -D NOBEEP # -D NOMEMLOCK

default: binaries # doc

binaries: seccure-key seccure-encrypt seccure-decrypt seccure-sign \
	seccure-verify

doc: seccure.1 seccure.1.html

install: default
	cp -i seccure-key /usr/bin
	ln -f /usr/bin/seccure-key /usr/bin/seccure-encrypt
	ln -f /usr/bin/seccure-key /usr/bin/seccure-decrypt
	ln -f /usr/bin/seccure-key /usr/bin/seccure-sign
	ln -f /usr/bin/seccure-key /usr/bin/seccure-verify
	cp -i seccure.1 /usr/share/man/man1

clean:
	rm -f *.o seccure-key seccure-encrypt seccure-decrypt seccure-sign \
	seccure-verify # seccure.1 seccure.1.html

rebuild: clean default



seccure-key: seccure.o numtheory.o ecc.o serialize.o protocol.o curves.o
	$(CC) $(CFLAGS) -o seccure-key -lgcrypt seccure.o numtheory.o ecc.o \
	curves.o serialize.o protocol.o

seccure-encrypt: seccure-key
	ln -f seccure-key seccure-encrypt

seccure-decrypt: seccure-key
	ln -f seccure-key seccure-decrypt

seccure-sign: seccure-key
	ln -f seccure-key seccure-sign

seccure-verify: seccure-key
	ln -f seccure-key seccure-verify

seccure.o: seccure.c
	$(CC) $(CFLAGS) -c seccure.c

numtheory.o: numtheory.c numtheory.h
	$(CC) $(CFLAGS) -c numtheory.c

ecc.o: ecc.c ecc.h
	$(CC) $(CFLAGS) -c ecc.c

curves.o: curves.c curves.h
	$(CC) $(CFLAGS) -c curves.c

serialize.o: serialize.c serialize.h
	$(CC) $(CFLAGS) -c serialize.c

protocol.o: protocol.c protocol.h
	$(CC) $(CFLAGS) -c protocol.c



seccure.1: seccure.manpage.xml
	xmltoman seccure.manpage.xml > seccure.1

seccure.1.html: seccure.manpage.xml
	xmlmantohtml seccure.manpage.xml > seccure.1.html

