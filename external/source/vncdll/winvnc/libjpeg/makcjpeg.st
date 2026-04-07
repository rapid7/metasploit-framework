; Project file for Independent JPEG Group's software
;
; This project file is for Atari ST/STE/TT systems using Pure C or Turbo C.
; Thanks to Frank Moehle (Frank.Moehle@arbi.informatik.uni-oldenburg.de),
; Dr. B. Setzepfandt (bernd@gina.uni-muenster.de),
; and Guido Vollbeding (guivol@esc.de).
;
; To use this file, rename it to cjpeg.prj.
; If you are using Turbo C, change filenames beginning with "pc..." to "tc..."
; Read installation instructions before trying to make the program!
;
;
;      * * * Output file * * *
cjpeg.ttp
;
; * * * COMPILER OPTIONS * * *  
.C[-P]        ; absolute calls
.C[-M]        ; and no string merging, folks
.C[-w-cln]    ; no "constant is long" warnings
.C[-w-par]    ; no "parameter xxxx unused"
.C[-w-rch]    ; no "unreachable code"
.C[-wsig]     ; warn if significant digits may be lost
=
; * * * * List of modules * * * * 
pcstart.o
cjpeg.c	(cdjpeg.h,jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h,cderror.h,jversion.h)
cdjpeg.c	(cdjpeg.h,jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h,cderror.h)
rdswitch.c	(cdjpeg.h,jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h,cderror.h)
rdppm.c	(cdjpeg.h,jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h,cderror.h)
rdgif.c	(cdjpeg.h,jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h,cderror.h)
rdtarga.c	(cdjpeg.h,jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h,cderror.h)
rdbmp.c	(cdjpeg.h,jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h,cderror.h)
rdrle.c	(cdjpeg.h,jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h,cderror.h)
libjpeg.lib        ; built by libjpeg.prj
pcfltlib.lib       ; floating point library
; the float library can be omitted if you've turned off DCT_FLOAT_SUPPORTED
pcstdlib.lib       ; standard library
pcextlib.lib       ; extended library
