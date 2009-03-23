$! make libz under VMS
$! written by Martin P.J. Zinser <m.zinser@gsi.de>
$!
$! Look for the compiler used
$!
$ ccopt = ""
$ if f$getsyi("HW_MODEL").ge.1024
$ then
$  ccopt = "/prefix=all"+ccopt
$  comp  = "__decc__=1"
$  if f$trnlnm("SYS").eqs."" then define sys sys$library:
$ else
$  if f$search("SYS$SYSTEM:DECC$COMPILER.EXE").eqs.""
$   then
$    comp  = "__vaxc__=1"
$    if f$trnlnm("SYS").eqs."" then define sys sys$library:
$   else
$    if f$trnlnm("SYS").eqs."" then define sys decc$library_include:
$    ccopt = "/decc/prefix=all"+ccopt
$    comp  = "__decc__=1"
$  endif
$ endif
$!
$! Build the thing plain or with mms
$!
$ write sys$output "Compiling Zlib sources ..."
$ if f$search("SYS$SYSTEM:MMS.EXE").eqs.""
$  then
$   dele example.obj;*,minigzip.obj;*
$   CALL MAKE adler32.OBJ "CC ''CCOPT' adler32" -
                adler32.c zlib.h zconf.h
$   CALL MAKE compress.OBJ "CC ''CCOPT' compress" -
                compress.c zlib.h zconf.h
$   CALL MAKE crc32.OBJ "CC ''CCOPT' crc32" -
                crc32.c zlib.h zconf.h
$   CALL MAKE deflate.OBJ "CC ''CCOPT' deflate" -
                deflate.c deflate.h zutil.h zlib.h zconf.h
$   CALL MAKE gzio.OBJ "CC ''CCOPT' gzio" -
                gzio.c zutil.h zlib.h zconf.h
$   CALL MAKE infblock.OBJ "CC ''CCOPT' infblock" -
                infblock.c zutil.h zlib.h zconf.h infblock.h
$   CALL MAKE infcodes.OBJ "CC ''CCOPT' infcodes" -
                infcodes.c zutil.h zlib.h zconf.h inftrees.h
$   CALL MAKE inffast.OBJ "CC ''CCOPT' inffast" -
                inffast.c zutil.h zlib.h zconf.h inffast.h
$   CALL MAKE inflate.OBJ "CC ''CCOPT' inflate" -
                inflate.c zutil.h zlib.h zconf.h infblock.h
$   CALL MAKE inftrees.OBJ "CC ''CCOPT' inftrees" -
                inftrees.c zutil.h zlib.h zconf.h inftrees.h
$   CALL MAKE infutil.OBJ "CC ''CCOPT' infutil" -
                infutil.c zutil.h zlib.h zconf.h inftrees.h infutil.h
$   CALL MAKE trees.OBJ "CC ''CCOPT' trees" -
                trees.c deflate.h zutil.h zlib.h zconf.h
$   CALL MAKE uncompr.OBJ "CC ''CCOPT' uncompr" -
                uncompr.c zlib.h zconf.h
$   CALL MAKE zutil.OBJ "CC ''CCOPT' zutil" -
                zutil.c zutil.h zlib.h zconf.h
$   write sys$output "Building Zlib ..."
$   CALL MAKE libz.OLB "lib/crea libz.olb *.obj" *.OBJ
$   write sys$output "Building example..."
$   CALL MAKE example.OBJ "CC ''CCOPT' example" -
                example.c zlib.h zconf.h
$   call make example.exe "LINK example,libz.olb/lib" example.obj libz.olb
$   write sys$output "Building minigzip..."
$   CALL MAKE minigzip.OBJ "CC ''CCOPT' minigzip" -
                minigzip.c zlib.h zconf.h
$   call make minigzip.exe - 
                "LINK minigzip,libz.olb/lib,x11vms:xvmsutils.olb/lib" - 
                minigzip.obj libz.olb
$  else
$   mms/macro=('comp')
$  endif
$ write sys$output "Zlib build completed"
$ exit
$!
$!
$MAKE: SUBROUTINE   !SUBROUTINE TO CHECK DEPENDENCIES
$ V = 'F$Verify(0)
$! P1 = What we are trying to make
$! P2 = Command to make it
$! P3 - P8  What it depends on
$
$ If F$Search(P1) .Eqs. "" Then Goto Makeit
$ Time = F$CvTime(F$File(P1,"RDT"))
$arg=3
$Loop:
$       Argument = P'arg
$       If Argument .Eqs. "" Then Goto Exit
$       El=0
$Loop2:
$       File = F$Element(El," ",Argument)
$       If File .Eqs. " " Then Goto Endl
$       AFile = ""
$Loop3:
$       OFile = AFile
$       AFile = F$Search(File)
$       If AFile .Eqs. "" .Or. AFile .Eqs. OFile Then Goto NextEl
$       If F$CvTime(F$File(AFile,"RDT")) .Ges. Time Then Goto Makeit
$       Goto Loop3
$NextEL:
$       El = El + 1
$       Goto Loop2
$EndL:
$ arg=arg+1
$ If arg .Le. 8 Then Goto Loop
$ Goto Exit
$
$Makeit:
$ VV=F$VERIFY(0)
$ write sys$output P2
$ 'P2
$ VV='F$Verify(VV)
$Exit:
$ If V Then Set Verify
$ENDSUBROUTINE
