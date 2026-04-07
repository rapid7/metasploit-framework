# Makefile for Independent JPEG Group's software

# This makefile is for Amiga systems using SAS C 6.0 and up.
# Thanks to Ed Hanway, Mark Rinfret, and Jim Zepeda.

# Read installation instructions before saying "make" !!

# The name of your C compiler:
CC= sc

# You may need to adjust these cc options:
# Uncomment the following lines for generic 680x0 version
ARCHFLAGS= cpu=any
SUFFIX=

# Uncomment the following lines for 68030-only version
#ARCHFLAGS= cpu=68030
#SUFFIX=.030

CFLAGS= nostackcheck data=near parms=register optimize $(ARCHFLAGS) \
	ignore=104 ignore=304 ignore=306
# ignore=104 disables warnings for mismatched const qualifiers
# ignore=304 disables warnings for variables being optimized out
# ignore=306 disables warnings for the inlining of functions
# Generally, we recommend defining any configuration symbols in jconfig.h,
# NOT via define switches here.

# Link-time cc options:
LDFLAGS= SC SD ND BATCH

# To link any special libraries, add the necessary commands here.
LDLIBS= LIB:scm.lib LIB:sc.lib

# Put here the object file name for the correct system-dependent memory
# manager file.  For Amiga we recommend jmemname.o.
SYSDEPMEM= jmemname.o

# miscellaneous OS-dependent stuff
# linker
LN= slink
# file deletion command
RM= delete quiet
# library (.lib) file creation command
AR= oml

# End of configurable options.


# source files: JPEG library proper
LIBSOURCES= jcapimin.c jcapistd.c jccoefct.c jccolor.c jcdctmgr.c jchuff.c \
        jcinit.c jcmainct.c jcmarker.c jcmaster.c jcomapi.c jcparam.c \
        jcphuff.c jcprepct.c jcsample.c jctrans.c jdapimin.c jdapistd.c \
        jdatadst.c jdatasrc.c jdcoefct.c jdcolor.c jddctmgr.c jdhuff.c \
        jdinput.c jdmainct.c jdmarker.c jdmaster.c jdmerge.c jdphuff.c \
        jdpostct.c jdsample.c jdtrans.c jerror.c jfdctflt.c jfdctfst.c \
        jfdctint.c jidctflt.c jidctfst.c jidctint.c jidctred.c jquant1.c \
        jquant2.c jutils.c jmemmgr.c
# memmgr back ends: compile only one of these into a working library
SYSDEPSOURCES= jmemansi.c jmemname.c jmemnobs.c jmemdos.c jmemmac.c
# source files: cjpeg/djpeg/jpegtran applications, also rdjpgcom/wrjpgcom
APPSOURCES= cjpeg.c djpeg.c jpegtran.c rdjpgcom.c wrjpgcom.c cdjpeg.c \
        rdcolmap.c rdswitch.c transupp.c rdppm.c wrppm.c rdgif.c wrgif.c \
        rdtarga.c wrtarga.c rdbmp.c wrbmp.c rdrle.c wrrle.c
SOURCES= $(LIBSOURCES) $(SYSDEPSOURCES) $(APPSOURCES)
# files included by source files
INCLUDES= jchuff.h jdhuff.h jdct.h jerror.h jinclude.h jmemsys.h jmorecfg.h \
        jpegint.h jpeglib.h jversion.h cdjpeg.h cderror.h transupp.h
# documentation, test, and support files
DOCS= README install.doc usage.doc cjpeg.1 djpeg.1 jpegtran.1 rdjpgcom.1 \
        wrjpgcom.1 wizard.doc example.c libjpeg.doc structure.doc \
        coderules.doc filelist.doc change.log
MKFILES= configure makefile.cfg makefile.ansi makefile.unix makefile.bcc \
        makefile.mc6 makefile.dj makefile.wat makefile.vc makelib.ds \
        makeapps.ds makeproj.mac makcjpeg.st makdjpeg.st makljpeg.st \
        maktjpeg.st makefile.manx makefile.sas makefile.mms makefile.vms \
        makvms.opt
CONFIGFILES= jconfig.cfg jconfig.bcc jconfig.mc6 jconfig.dj jconfig.wat \
        jconfig.vc jconfig.mac jconfig.st jconfig.manx jconfig.sas \
        jconfig.vms
CONFIGUREFILES= config.guess config.sub install-sh ltconfig ltmain.sh
OTHERFILES= jconfig.doc ckconfig.c ansi2knr.c ansi2knr.1 jmemdosa.asm
TESTFILES= testorig.jpg testimg.ppm testimg.bmp testimg.jpg testprog.jpg \
        testimgp.jpg
DISTFILES= $(DOCS) $(MKFILES) $(CONFIGFILES) $(SOURCES) $(INCLUDES) \
        $(CONFIGUREFILES) $(OTHERFILES) $(TESTFILES)
# library object files common to compression and decompression
COMOBJECTS= jcomapi.o jutils.o jerror.o jmemmgr.o $(SYSDEPMEM)
# compression library object files
CLIBOBJECTS= jcapimin.o jcapistd.o jctrans.o jcparam.o jdatadst.o jcinit.o \
        jcmaster.o jcmarker.o jcmainct.o jcprepct.o jccoefct.o jccolor.o \
        jcsample.o jchuff.o jcphuff.o jcdctmgr.o jfdctfst.o jfdctflt.o \
        jfdctint.o
# decompression library object files
DLIBOBJECTS= jdapimin.o jdapistd.o jdtrans.o jdatasrc.o jdmaster.o \
        jdinput.o jdmarker.o jdhuff.o jdphuff.o jdmainct.o jdcoefct.o \
        jdpostct.o jddctmgr.o jidctfst.o jidctflt.o jidctint.o jidctred.o \
        jdsample.o jdcolor.o jquant1.o jquant2.o jdmerge.o
# These objectfiles are included in libjpeg.lib
LIBOBJECTS= $(CLIBOBJECTS) $(DLIBOBJECTS) $(COMOBJECTS)
# object files for sample applications (excluding library files)
COBJECTS= cjpeg.o rdppm.o rdgif.o rdtarga.o rdrle.o rdbmp.o rdswitch.o \
        cdjpeg.o
DOBJECTS= djpeg.o wrppm.o wrgif.o wrtarga.o wrrle.o wrbmp.o rdcolmap.o \
        cdjpeg.o
TROBJECTS= jpegtran.o rdswitch.o cdjpeg.o transupp.o


all: libjpeg.lib cjpeg$(SUFFIX) djpeg$(SUFFIX) jpegtran$(SUFFIX) rdjpgcom$(SUFFIX) wrjpgcom$(SUFFIX)

# note: do several AR steps to avoid command line length limitations

libjpeg.lib: $(LIBOBJECTS)
	-$(RM) libjpeg.lib
	$(AR) libjpeg.lib r $(CLIBOBJECTS)
	$(AR) libjpeg.lib r $(DLIBOBJECTS)
	$(AR) libjpeg.lib r $(COMOBJECTS)

cjpeg$(SUFFIX): $(COBJECTS) libjpeg.lib
	$(LN) <WITH <
$(LDFLAGS)
TO cjpeg$(SUFFIX)
FROM LIB:c.o $(COBJECTS)
LIB libjpeg.lib $(LDLIBS)
<

djpeg$(SUFFIX): $(DOBJECTS) libjpeg.lib
	$(LN) <WITH <
$(LDFLAGS)
TO djpeg$(SUFFIX)
FROM LIB:c.o $(DOBJECTS)
LIB libjpeg.lib $(LDLIBS)
<

jpegtran$(SUFFIX): $(TROBJECTS) libjpeg.lib
	$(LN) <WITH <
$(LDFLAGS)
TO jpegtran$(SUFFIX)
FROM LIB:c.o $(TROBJECTS)
LIB libjpeg.lib $(LDLIBS)
<

rdjpgcom$(SUFFIX): rdjpgcom.o
	$(LN) <WITH <
$(LDFLAGS)
TO rdjpgcom$(SUFFIX)
FROM LIB:c.o rdjpgcom.o
LIB $(LDLIBS)
<

wrjpgcom$(SUFFIX): wrjpgcom.o
	$(LN) <WITH <
$(LDFLAGS)
TO wrjpgcom$(SUFFIX)
FROM LIB:c.o wrjpgcom.o
LIB $(LDLIBS)
<

jconfig.h: jconfig.doc
	echo You must prepare a system-dependent jconfig.h file.
	echo Please read the installation directions in install.doc.
	exit 1

clean:
	-$(RM) *.o cjpeg djpeg jpegtran cjpeg.030 djpeg.030 jpegtran.030
	-$(RM) rdjpgcom wrjpgcom rdjpgcom.030 wrjpgcom.030
	-$(RM) libjpeg.lib core testout*.*

test: cjpeg djpeg jpegtran
	-$(RM) testout*.*
	djpeg -dct int -ppm -outfile testout.ppm  testorig.jpg
	djpeg -dct int -bmp -colors 256 -outfile testout.bmp  testorig.jpg
	cjpeg -dct int -outfile testout.jpg  testimg.ppm
	djpeg -dct int -ppm -outfile testoutp.ppm testprog.jpg
	cjpeg -dct int -progressive -opt -outfile testoutp.jpg testimg.ppm
	jpegtran -outfile testoutt.jpg testprog.jpg
	cmp testimg.ppm testout.ppm
	cmp testimg.bmp testout.bmp
	cmp testimg.jpg testout.jpg
	cmp testimg.ppm testoutp.ppm
	cmp testimgp.jpg testoutp.jpg
	cmp testorig.jpg testoutt.jpg


jcapimin.o: jcapimin.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jcapistd.o: jcapistd.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jccoefct.o: jccoefct.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jccolor.o: jccolor.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jcdctmgr.o: jcdctmgr.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jdct.h
jchuff.o: jchuff.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jchuff.h
jcinit.o: jcinit.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jcmainct.o: jcmainct.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jcmarker.o: jcmarker.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jcmaster.o: jcmaster.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jcomapi.o: jcomapi.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jcparam.o: jcparam.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jcphuff.o: jcphuff.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jchuff.h
jcprepct.o: jcprepct.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jcsample.o: jcsample.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jctrans.o: jctrans.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jdapimin.o: jdapimin.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jdapistd.o: jdapistd.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jdatadst.o: jdatadst.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h
jdatasrc.o: jdatasrc.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h
jdcoefct.o: jdcoefct.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jdcolor.o: jdcolor.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jddctmgr.o: jddctmgr.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jdct.h
jdhuff.o: jdhuff.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jdhuff.h
jdinput.o: jdinput.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jdmainct.o: jdmainct.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jdmarker.o: jdmarker.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jdmaster.o: jdmaster.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jdmerge.o: jdmerge.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jdphuff.o: jdphuff.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jdhuff.h
jdpostct.o: jdpostct.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jdsample.o: jdsample.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jdtrans.o: jdtrans.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jerror.o: jerror.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jversion.h jerror.h
jfdctflt.o: jfdctflt.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jdct.h
jfdctfst.o: jfdctfst.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jdct.h
jfdctint.o: jfdctint.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jdct.h
jidctflt.o: jidctflt.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jdct.h
jidctfst.o: jidctfst.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jdct.h
jidctint.o: jidctint.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jdct.h
jidctred.o: jidctred.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jdct.h
jquant1.o: jquant1.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jquant2.o: jquant2.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jutils.o: jutils.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h
jmemmgr.o: jmemmgr.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jmemsys.h
jmemansi.o: jmemansi.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jmemsys.h
jmemname.o: jmemname.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jmemsys.h
jmemnobs.o: jmemnobs.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jmemsys.h
jmemdos.o: jmemdos.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jmemsys.h
jmemmac.o: jmemmac.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h jmemsys.h
cjpeg.o: cjpeg.c cdjpeg.h jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h cderror.h jversion.h
djpeg.o: djpeg.c cdjpeg.h jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h cderror.h jversion.h
jpegtran.o: jpegtran.c cdjpeg.h jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h cderror.h transupp.h jversion.h
rdjpgcom.o: rdjpgcom.c jinclude.h jconfig.h
wrjpgcom.o: wrjpgcom.c jinclude.h jconfig.h
cdjpeg.o: cdjpeg.c cdjpeg.h jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h cderror.h
rdcolmap.o: rdcolmap.c cdjpeg.h jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h cderror.h
rdswitch.o: rdswitch.c cdjpeg.h jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h cderror.h
transupp.o: transupp.c jinclude.h jconfig.h jpeglib.h jmorecfg.h jpegint.h jerror.h transupp.h
rdppm.o: rdppm.c cdjpeg.h jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h cderror.h
wrppm.o: wrppm.c cdjpeg.h jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h cderror.h
rdgif.o: rdgif.c cdjpeg.h jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h cderror.h
wrgif.o: wrgif.c cdjpeg.h jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h cderror.h
rdtarga.o: rdtarga.c cdjpeg.h jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h cderror.h
wrtarga.o: wrtarga.c cdjpeg.h jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h cderror.h
rdbmp.o: rdbmp.c cdjpeg.h jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h cderror.h
wrbmp.o: wrbmp.c cdjpeg.h jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h cderror.h
rdrle.o: rdrle.c cdjpeg.h jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h cderror.h
wrrle.o: wrrle.c cdjpeg.h jinclude.h jconfig.h jpeglib.h jmorecfg.h jerror.h cderror.h
