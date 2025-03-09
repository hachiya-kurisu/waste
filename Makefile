VERSION = 0.1
OS != uname -s

-include Makefile.$(OS)

CFLAGS += -DVERSION=\"${VERSION}\"
CFLAGS += -DNAME=\"waste\"
CFLAGS += -Wall -Wextra -std=c99 -pedantic

PREFIX ?= /usr/local
MANDIR ?= /share/man

LIBS += -ltls -lssl -lcrypto -lz

all: waste

config.h:
	cp config.def.h $@

waste: config.h src/waste.c
	${CC} ${CFLAGS} ${LDFLAGS} -L. -o $@ src/waste.c ${LIBS}
	strip $@

install:
	install waste ${DESTDIR}${PREFIX}/bin/waste

cert:
	openssl genrsa -out waste.key 2048
	openssl req -new -key waste.key -out waste.csr
	openssl x509 -req -days 999999 -in waste.csr -signkey waste.key -out waste.crt

README.md: README.gmi
	sisyphus -f markdown <README.gmi >README.md

doc: README.md

push:
	got send
	git push github

clean:
	rm -f waste

again: clean all

release: push
	git push github --tags
