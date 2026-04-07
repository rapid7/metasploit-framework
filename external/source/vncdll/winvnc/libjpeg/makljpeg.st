; Project file for Independent JPEG Group's software
;
; This project file is for Atari ST/STE/TT systems using Pure C or Turbo C.
; Thanks to Frank Moehle (Frank.Moehle@arbi.informatik.uni-oldenburg.de),
; Dr. B. Setzepfandt (bernd@gina.uni-muenster.de),
; and Guido Vollbeding (guivol@esc.de).
;
; To use this file, rename it to libjpeg.prj.
; Read installation instructions before trying to make the program!
;
;
;      * * * Output file * * *
libjpeg.lib
;
; * * * COMPILER OPTIONS * * *  
.C[-P]        ; absolute calls
.C[-M]        ; and no string merging, folks
.C[-w-cln]    ; no "constant is long" warnings
.C[-w-par]    ; no "parameter xxxx unused"
.C[-w-rch]    ; no "unreachable code"
.C[-wsig]     ; warn if significant digits may be lost
.L[-J]        ; link new Obj-format (so we get a library)
=
; * * * * List of modules * * * * 
jcapimin.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jcapistd.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jccoefct.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jccolor.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jcdctmgr.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h,jdct.h)
jchuff.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h,jchuff.h)
jcinit.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jcmainct.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jcmarker.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jcmaster.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jcomapi.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jcparam.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jcphuff.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h,jchuff.h)
jcprepct.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jcsample.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jctrans.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jdapimin.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jdapistd.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jdatadst.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h)
jdatasrc.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h)
jdcoefct.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jdcolor.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jddctmgr.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h,jdct.h)
jdhuff.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h,jdhuff.h)
jdinput.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jdmainct.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jdmarker.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jdmaster.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jdmerge.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jdphuff.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h,jdhuff.h)
jdpostct.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jdsample.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jdtrans.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jerror.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jversion.h,jerror.h)
jfdctflt.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h,jdct.h)
jfdctfst.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h,jdct.h)
jfdctint.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h,jdct.h)
jidctflt.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h,jdct.h)
jidctfst.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h,jdct.h)
jidctint.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h,jdct.h)
jidctred.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h,jdct.h)
jquant1.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jquant2.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jutils.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h)
jmemmgr.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h,jmemsys.h)
jmemansi.c	(jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jpegint.h,jerror.h,jmemsys.h)
