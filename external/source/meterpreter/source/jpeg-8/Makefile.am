## Process this file with automake to produce Makefile.in
#
#  Automake Makefile for the JPEG library
#
#  This file is written by Bob Friesenhahn, Guido Vollbeding
#

# Sources to build library
LIBSOURCES = jaricom.c jcapimin.c jcapistd.c jcarith.c jccoefct.c jccolor.c \
        jcdctmgr.c jchuff.c jcinit.c jcmainct.c jcmarker.c jcmaster.c \
        jcomapi.c jcparam.c jcprepct.c jcsample.c jctrans.c jdapimin.c \
        jdapistd.c jdarith.c jdatadst.c jdatasrc.c jdcoefct.c jdcolor.c \
        jddctmgr.c jdhuff.c jdinput.c jdmainct.c jdmarker.c jdmaster.c \
        jdmerge.c jdpostct.c jdsample.c jdtrans.c jerror.c jfdctflt.c \
        jfdctfst.c jfdctint.c jidctflt.c jidctfst.c jidctint.c jquant1.c \
        jquant2.c jutils.c jmemmgr.c @MEMORYMGR@.c

# System dependent sources
SYSDEPSOURCES = jmemansi.c jmemname.c jmemnobs.c jmemdos.c jmemmac.c

# Headers which are installed to support the library
INSTINCLUDES  = jerror.h jmorecfg.h jpeglib.h

# Headers which are not installed
OTHERINCLUDES = cderror.h cdjpeg.h jdct.h jinclude.h jmemsys.h jpegint.h \
        jversion.h transupp.h

# Manual pages (Automake uses 'MANS' for itself)
DISTMANS= cjpeg.1 djpeg.1 jpegtran.1 rdjpgcom.1 wrjpgcom.1

# Other documentation files
DOCS= README install.txt usage.txt wizard.txt example.c libjpeg.txt \
        structure.txt coderules.txt filelist.txt change.log

# Makefiles for various systems
MKFILES= configure Makefile.in makefile.ansi makefile.unix makefile.bcc \
        makefile.mc6 makefile.dj makefile.wat makefile.vc makejdsw.vc6 \
        makeadsw.vc6 makejdep.vc6 makejdsp.vc6 makejmak.vc6 makecdep.vc6 \
        makecdsp.vc6 makecmak.vc6 makeddep.vc6 makeddsp.vc6 makedmak.vc6 \
        maketdep.vc6 maketdsp.vc6 maketmak.vc6 makerdep.vc6 makerdsp.vc6 \
        makermak.vc6 makewdep.vc6 makewdsp.vc6 makewmak.vc6 makejsln.vc9 \
        makeasln.vc9 makejvcp.vc9 makecvcp.vc9 makedvcp.vc9 maketvcp.vc9 \
        makervcp.vc9 makewvcp.vc9 makeproj.mac makcjpeg.st makdjpeg.st \
        makljpeg.st maktjpeg.st makefile.manx makefile.sas makefile.mms \
        makefile.vms makvms.opt

# Configuration files
CONFIGFILES= jconfig.cfg jconfig.bcc jconfig.mc6 jconfig.dj jconfig.wat \
        jconfig.vc jconfig.mac jconfig.st jconfig.manx jconfig.sas \
        jconfig.vms

# Support scripts for configure
CONFIGUREFILES= config.guess config.sub install-sh ltmain.sh depcomp missing

# Miscellaneous support files
OTHERFILES= jconfig.txt ckconfig.c ansi2knr.c ansi2knr.1 jmemdosa.asm \
        libjpeg.map

# Test support files
TESTFILES= testorig.jpg testimg.ppm testimg.bmp testimg.jpg testprog.jpg \
        testimgp.jpg

# libtool libraries to build
lib_LTLIBRARIES = libjpeg.la

# Library sources for libjpeg.la
libjpeg_la_SOURCES = $(LIBSOURCES)

# LDFLAGS for libjpeg.la
libjpeg_la_LDFLAGS = -no-undefined \
        -version-info $(JPEG_LIB_VERSION)

if HAVE_LD_VERSION_SCRIPT
  libjpeg_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libjpeg.map
endif

# Executables to build
bin_PROGRAMS = cjpeg djpeg jpegtran rdjpgcom wrjpgcom

# Executable sources & libs
cjpeg_SOURCES    = cjpeg.c rdppm.c rdgif.c rdtarga.c rdrle.c rdbmp.c \
        rdswitch.c cdjpeg.c
cjpeg_LDADD      = libjpeg.la
djpeg_SOURCES    = djpeg.c wrppm.c wrgif.c wrtarga.c wrrle.c wrbmp.c \
        rdcolmap.c cdjpeg.c
djpeg_LDADD      = libjpeg.la
jpegtran_SOURCES = jpegtran.c rdswitch.c cdjpeg.c transupp.c
jpegtran_LDADD   = libjpeg.la
rdjpgcom_SOURCES = rdjpgcom.c
wrjpgcom_SOURCES = wrjpgcom.c

# Manual pages to install
man_MANS = $(DISTMANS)

# Headers to install
include_HEADERS = $(INSTINCLUDES)

# Other distributed headers
noinst_HEADERS = $(OTHERINCLUDES)

# Other distributed files
EXTRA_DIST =  $(DOCS) $(DISTMANS) $(MKFILES) $(CONFIGFILES) $(SYSDEPSOURCES) \
        $(OTHERFILES) $(TESTFILES)

# Files to be cleaned
CLEANFILES = testout.ppm testout.bmp testout.jpg testoutp.ppm testoutp.jpg \
        testoutt.jpg

# Install jconfig.h
install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(includedir)
	$(INSTALL_HEADER) jconfig.h $(DESTDIR)$(includedir)/jconfig.h

# Uninstall jconfig.h
uninstall-local:
	rm -f $(DESTDIR)$(includedir)/jconfig.h

# Run tests
test: check-local
check-local:
	$(RM) testout*
	./djpeg -dct int -ppm -outfile testout.ppm  $(srcdir)/testorig.jpg
	./djpeg -dct int -bmp -colors 256 -outfile testout.bmp  $(srcdir)/testorig.jpg
	./cjpeg -dct int -outfile testout.jpg  $(srcdir)/testimg.ppm
	./djpeg -dct int -ppm -outfile testoutp.ppm $(srcdir)/testprog.jpg
	./cjpeg -dct int -progressive -opt -outfile testoutp.jpg $(srcdir)/testimg.ppm
	./jpegtran -outfile testoutt.jpg $(srcdir)/testprog.jpg
	cmp $(srcdir)/testimg.ppm testout.ppm
	cmp $(srcdir)/testimg.bmp testout.bmp
	cmp $(srcdir)/testimg.jpg testout.jpg
	cmp $(srcdir)/testimg.ppm testoutp.ppm
	cmp $(srcdir)/testimgp.jpg testoutp.jpg
	cmp $(srcdir)/testorig.jpg testoutt.jpg
