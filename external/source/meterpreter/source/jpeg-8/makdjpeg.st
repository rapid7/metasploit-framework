; Project file for Independent JPEG Group's software
;
; This project file is for Atari ST/STE/TT systems using Pure C or Turbo C.
; Thanks to Frank Moehle, B. Setzepfandt, and Guido Vollbeding.
;
; To use this file, rename it to djpeg.prj.
; If you are using Turbo C, change filenames beginning with "pc..." to "tc..."
; Read installation instructions before trying to make the program!
;
;
;      * * * Output file * * *
djpeg.ttp
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
djpeg.c		(cdjpeg.h,jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h,cderror.h,jversion.h)
cdjpeg.c	(cdjpeg.h,jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h,cderror.h)
rdcolmap.c	(cdjpeg.h,jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h,cderror.h)
wrppm.c		(cdjpeg.h,jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h,cderror.h)
wrgif.c		(cdjpeg.h,jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h,cderror.h)
wrtarga.c	(cdjpeg.h,jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h,cderror.h)
wrbmp.c		(cdjpeg.h,jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h,cderror.h)
wrrle.c		(cdjpeg.h,jinclude.h,jconfig.h,jpeglib.h,jmorecfg.h,jerror.h,cderror.h)
libjpeg.lib        ; built by libjpeg.prj
pcfltlib.lib       ; floating point library
; the float library can be omitted if you've turned off DCT_FLOAT_SUPPORTED
pcstdlib.lib       ; standard library
pcextlib.lib       ; extended library
