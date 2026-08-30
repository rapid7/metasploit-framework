##############################################################################
##
##  Makefile for Detours.
##
##  Microsoft Research Detours Package, Version 2.1.
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##
##############################################################################

ROOT = ..

INCD = $(ROOT)\include
LIBD = $(ROOT)\lib
BIND = $(ROOT)\bin

!IF "$(DETOURS_SOURCE_BROWSING)" == ""
DETOURS_SOURCE_BROWSING = 0
!ENDIF

############################################## Determine Processor Build Type.
##
!IF "$(DETOURS_TARGET_PROCESSOR)" == ""
DETOURS_TARGET_PROCESSOR = $(PROCESSOR_ARCHITEW6432)
!ENDIF
!IF "$(DETOURS_TARGET_PROCESSOR)" == ""
DETOURS_TARGET_PROCESSOR = $(PROCESSOR_ARCHITECTURE)
!ENDIF

!IF "$(DETOURS_TARGET_PROCESSOR)" == "x86"
DETOURS_TARGET_PROCESSOR=X86
!ENDIF

!IF "$(DETOURS_TARGET_PROCESSOR)" == "AMD64"
#!MESSAGE Building for 64-bit AMD64.
DETOURS_TARGET_PROCESSOR=X64
!ENDIF

!IF "$(DETOURS_TARGET_PROCESSOR)" == "X64"
!MESSAGE Building for 64-bit X64.
DETOURS_SOURCE_BROWSING = 0
!ELSEIF "$(DETOURS_TARGET_PROCESSOR)" == "IA64"
!MESSAGE Building for 64-bit IA64.
!ELSEIF "$(DETOURS_TARGET_PROCESSOR)" == "X86"
!MESSAGE Building for 32-bit X86.
!ELSE
!MESSAGE Note: To select the target processor architecture set either
!MESSAGE       PROCESSOR_ARCHITECTURE or DETOURS_TARGET_PROCESSOR.
!MESSAGE
!ERROR Unknown target processor: $(DETOURS_TARGET_ARCHITECTURE)
!ENDIF

##############################################################################
##
CFLAGS=/nologo /W4 /WX /Zi /MTd /Gy /Gm- /Zl /O1
!IF $(DETOURS_SOURCE_BROWSING)==1
CFLAGS=$(CFLAGS) /FR
!ELSE
CFLAGS=$(CFLAGS) /DWIN32_LEAN_AND_MEAN /D_WIN32_WINNT=0x403
!ENDIF

#/D_CRT_INSECURE_DEPRECATE

LIBFLAGS=/nologo
LINKFLAGS=/release

!IF "$(DETOURS_TARGET_PROCESSOR)" == "X86"

CFLAGS=$(CFLAGS) /Gs /DDETOURS_X86=1 /D_X86_
LIBFLAGS=$(LIBFLAGS) /debug
DLLENTRY=_DllMainCRTStartup@12
LINKFLAGS=$(LINKFLAGS) /machine:x86

!ELSEIF "$(DETOURS_TARGET_PROCESSOR)" == "X64"

CFLAGS=$(CFLAGS) /D_WIN64 /DDETOURS_X64=1 /D_AMD64_ /Wp64
LIBFLAGS=$(LIBFLAGS)
DLLENTRY=_DllMainCRTStartup
LINKFLAGS=$(LINKFLAGS) /machine:amd64

!ELSEIF "$(DETOURS_TARGET_PROCESSOR)" == "IA64"

CFLAGS=$(CFLAGS) /D_WIN64 /DDETOURS_IA64=1 /D_IA64_ /wd4163 /Wp64
LIBFLAGS=$(LIBFLAGS)
DLLENTRY=_DllMainCRTStartup
LINKFLAGS=$(LINKFLAGS) /machine:ia64

!ENDIF

OBJS = \
	detours.obj	\
	modules.obj	\
	disasm.obj	\
	image.obj	\
	creatwth.obj	\

##############################################################################
##
.SUFFIXES: .cpp .h .obj
.cpp.obj:
	$(CC) /nologo $(CFLAGS)  "/Fd$(LIBD)\detours.pdb" /Fo$*.obj /c "$(MAKEDIR)\$*.cpp"

##############################################################################

all: dirs \
	"$(BIND)\detoured.dll"	\
	"$(LIBD)\detours.lib"	\
	"$(INCD)\detours.h"	\
!IF $(DETOURS_SOURCE_BROWSING)==1
	detours.bsc \
!endif

##############################################################################

clean:
	@-del *.obj *.pdb *.ilk *.exe *.sbr *.bsc *.res *~ 2>nul
	@-del $(LIBD)\detours.pdb $(LIBD)\detours.lib 2>nul
	@-del $(BIND)\detoured.pdb $(BIND)\detoured.pdb 2>nul

##############################################################################

dirs:
	if not exist "$(INCD)" mkdir "$(INCD)"
	if not exist "$(LIBD)" mkdir "$(LIBD)"
	if not exist "$(BIND)" mkdir "$(BIND)"

detours.bsc : $(OBJS)
	bscmake /v /n /o $@ $(OBJS:.obj=.sbr)

"$(ROOT)\lib\detours.lib" : $(OBJS)
	lib $(LIBFLAGS) /out:$@ $(OBJS)

"$(ROOT)\include\detours.h" : detours.h
	copy detours.h $@

detoured.res : detoured.rc
	rc detoured.rc

$(BIND)\detoured.dll: detoured.cpp detoured.res
	cl /LD $(CFLAGS) /Fe$@ /Fd$(BIND)\detoured.pdb detoured.cpp \
		/link $(LINKFLAGS) /base:0xf000000 /incremental:no /subsystem:console \
		/entry:DllMain /implib:$(LIBD)\detoured.lib \
		/export:Detoured kernel32.lib detoured.res

$(BIND)\detoured.bsc : detoured.obj
	bscmake /v /n /o $@ detoured.sbr

detours.obj : detours.cpp detours.h
modules.obj : modules.cpp detours.h
disasm.obj : disasm.cpp detours.h
image.obj : image.cpp detours.h
creatwth.obj : creatwth.cpp detours.h

test: all
	cd $(MAKEDIR)\..\samples\slept
	nmake /nologo test
	cd $(MAKEDIR)

################################################################# End of File.
