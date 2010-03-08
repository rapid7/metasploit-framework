# Makefile for zlib
# Copyright (C) 1995-2002 Jean-loup Gailly.
# For conditions of distribution and use, see copyright notice in zlib.h 

# To compile and test, type:
#   ./configure; make test
# The call of configure is optional if you don't have special requirements
# If you wish to build zlib as a shared library, use: ./configure -s

# To install /usr/local/lib/libz.* and /usr/local/include/zlib.h, type:
#    make install
# To install in $HOME instead of /usr/local, use:
#    make install prefix=$HOME

CC=cc

CFLAGS=-O
#CFLAGS=-O -DMAX_WBITS=14 -DMAX_MEM_LEVEL=7
#CFLAGS=-g -DDEBUG
#CFLAGS=-O3 -Wall -Wwrite-strings -Wpointer-arith -Wconversion \
#           -Wstrict-prototypes -Wmissing-prototypes

LDFLAGS=-L. -lz
LDSHARED=$(CC)
CPP=$(CC) -E

VER=1.1.4
LIBS=libz.a
SHAREDLIB=libz.so

AR=ar rc
RANLIB=ranlib
TAR=tar
SHELL=/bin/sh

prefix = /usr/local
exec_prefix = ${prefix}
libdir = ${exec_prefix}/lib
includedir = ${prefix}/include

OBJS = adler32.o compress.o crc32.o gzio.o uncompr.o deflate.o trees.o \
       zutil.o inflate.o infblock.o inftrees.o infcodes.o infutil.o inffast.o

OBJA =
# to use the asm code: make OBJA=match.o

TEST_OBJS = example.o minigzip.o

DISTFILES = README FAQ INDEX ChangeLog configure Make*[a-z0-9] *.[ch] *.mms \
  algorithm.txt zlib.3 zlib.html \
  msdos/Make*[a-z0-9] msdos/zlib.def msdos/zlib.rc \
  nt/Make*[a-z0-9] nt/zlib.dnt amiga/Make*.??? os2/M*.os2 os2/zlib.def \
  contrib/RE*.contrib contrib/*.txt contrib/asm386/*.asm contrib/asm386/*.c \
  contrib/asm386/*.bat contrib/asm386/zlibvc.d?? contrib/asm[56]86/*.?86 \
  contrib/asm[56]86/*.S contrib/iostream/*.cpp \
  contrib/iostream/*.h  contrib/iostream2/*.h contrib/iostream2/*.cpp \
  contrib/untgz/Makefile contrib/untgz/*.c contrib/untgz/*.w32 \
  contrib/minizip/[CM]*[pe] contrib/minizip/*.[ch] contrib/minizip/*.[td]?? \
  contrib/delphi*/*.???

all: example minigzip

test: all
	@LD_LIBRARY_PATH=.:$(LD_LIBRARY_PATH) ; export LD_LIBRARY_PATH; \
	echo hello world | ./minigzip | ./minigzip -d || \
	  echo '		*** minigzip test FAILED ***' ; \
	if ./example; then \
	  echo '		*** zlib test OK ***'; \
	else \
	  echo '		*** zlib test FAILED ***'; \
	fi

libz.a: $(OBJS) $(OBJA)
	$(AR) $@ $(OBJS) $(OBJA)
	-@ ($(RANLIB) $@ || true) >/dev/null 2>&1

match.o: match.S
	$(CPP) match.S > _match.s
	$(CC) -c _match.s
	mv _match.o match.o
	rm -f _match.s

$(SHAREDLIB).$(VER): $(OBJS)
	$(LDSHARED) -o $@ $(OBJS)
	rm -f $(SHAREDLIB) $(SHAREDLIB).1
	ln -s $@ $(SHAREDLIB)
	ln -s $@ $(SHAREDLIB).1

example: example.o $(LIBS)
	$(CC) $(CFLAGS) -o $@ example.o $(LDFLAGS)

minigzip: minigzip.o $(LIBS)
	$(CC) $(CFLAGS) -o $@ minigzip.o $(LDFLAGS)

install: $(LIBS)
	-@if [ ! -d $(includedir)  ]; then mkdir $(includedir); fi
	-@if [ ! -d $(libdir) ]; then mkdir $(libdir); fi
	cp zlib.h zconf.h $(includedir)
	chmod 644 $(includedir)/zlib.h $(includedir)/zconf.h
	cp $(LIBS) $(libdir)
	cd $(libdir); chmod 755 $(LIBS)
	-@(cd $(libdir); $(RANLIB) libz.a || true) >/dev/null 2>&1
	cd $(libdir); if test -f $(SHAREDLIB).$(VER); then \
	  rm -f $(SHAREDLIB) $(SHAREDLIB).1; \
	  ln -s $(SHAREDLIB).$(VER) $(SHAREDLIB); \
	  ln -s $(SHAREDLIB).$(VER) $(SHAREDLIB).1; \
	  (ldconfig || true)  >/dev/null 2>&1; \
	fi
# The ranlib in install is needed on NeXTSTEP which checks file times
# ldconfig is for Linux

uninstall:
	cd $(includedir); \
	v=$(VER); \
	if test -f zlib.h; then \
	  v=`sed -n '/VERSION "/s/.*"\(.*\)".*/\1/p' < zlib.h`; \
          rm -f zlib.h zconf.h; \
	fi; \
	cd $(libdir); rm -f libz.a; \
	if test -f $(SHAREDLIB).$$v; then \
	  rm -f $(SHAREDLIB).$$v $(SHAREDLIB) $(SHAREDLIB).1; \
	fi

clean:
	rm -f *.o *~ example minigzip libz.a libz.so* foo.gz so_locations \
	   _match.s maketree

distclean:	clean

zip:
	mv Makefile Makefile~; cp -p Makefile.in Makefile
	rm -f test.c ztest*.c contrib/minizip/test.zip
	v=`sed -n -e 's/\.//g' -e '/VERSION "/s/.*"\(.*\)".*/\1/p' < zlib.h`;\
	zip -ul9 zlib$$v $(DISTFILES)
	mv Makefile~ Makefile

dist:
	mv Makefile Makefile~; cp -p Makefile.in Makefile
	rm -f test.c ztest*.c contrib/minizip/test.zip
	d=zlib-`sed -n '/VERSION "/s/.*"\(.*\)".*/\1/p' < zlib.h`;\
	rm -f $$d.tar.gz; \
	if test ! -d ../$$d; then rm -f ../$$d; ln -s `pwd` ../$$d; fi; \
	files=""; \
	for f in $(DISTFILES); do files="$$files $$d/$$f"; done; \
	cd ..; \
	GZIP=-9 $(TAR) chofz $$d/$$d.tar.gz $$files; \
	if test ! -d $$d; then rm -f $$d; fi
	mv Makefile~ Makefile

tags:	
	etags *.[ch]

depend:
	makedepend -- $(CFLAGS) -- *.[ch]

# DO NOT DELETE THIS LINE -- make depend depends on it.

adler32.o: zlib.h zconf.h
compress.o: zlib.h zconf.h
crc32.o: zlib.h zconf.h
deflate.o: deflate.h zutil.h zlib.h zconf.h
example.o: zlib.h zconf.h
gzio.o: zutil.h zlib.h zconf.h
infblock.o: infblock.h inftrees.h infcodes.h infutil.h zutil.h zlib.h zconf.h
infcodes.o: zutil.h zlib.h zconf.h
infcodes.o: inftrees.h infblock.h infcodes.h infutil.h inffast.h
inffast.o: zutil.h zlib.h zconf.h inftrees.h
inffast.o: infblock.h infcodes.h infutil.h inffast.h
inflate.o: zutil.h zlib.h zconf.h infblock.h
inftrees.o: zutil.h zlib.h zconf.h inftrees.h
infutil.o: zutil.h zlib.h zconf.h infblock.h inftrees.h infcodes.h infutil.h
minigzip.o:  zlib.h zconf.h 
trees.o: deflate.h zutil.h zlib.h zconf.h trees.h
uncompr.o: zlib.h zconf.h
zutil.o: zutil.h zlib.h zconf.h  
