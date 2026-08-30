# Microsoft Developer Studio Generated NMAKE File, Format Version 4.20
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

!IF "$(CFG)" == ""
CFG=cjpeg - Win32
!MESSAGE No configuration specified.  Defaulting to cjpeg - Win32.
!ENDIF 

!IF "$(CFG)" != "cjpeg - Win32" && "$(CFG)" != "djpeg - Win32" &&\
 "$(CFG)" != "jpegtran - Win32" && "$(CFG)" != "rdjpgcom - Win32" &&\
 "$(CFG)" != "wrjpgcom - Win32"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "apps.mak" CFG="cjpeg - Win32"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "cjpeg - Win32" (based on "Win32 (x86) Console Application")
!MESSAGE "djpeg - Win32" (based on "Win32 (x86) Console Application")
!MESSAGE "jpegtran - Win32" (based on "Win32 (x86) Console Application")
!MESSAGE "rdjpgcom - Win32" (based on "Win32 (x86) Console Application")
!MESSAGE "wrjpgcom - Win32" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 
################################################################################
# Begin Project
# PROP Target_Last_Scanned "cjpeg - Win32"
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "cjpeg - Win32"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "cjpeg\Release"
# PROP BASE Intermediate_Dir "cjpeg\Release"
# PROP BASE Target_Dir "cjpeg"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "cjpeg\Release"
# PROP Intermediate_Dir "cjpeg\Release"
# PROP Target_Dir "cjpeg"
OUTDIR=.\cjpeg\Release
INTDIR=.\cjpeg\Release

ALL : "$(OUTDIR)\cjpeg.exe"

CLEAN : 
	-@erase "$(INTDIR)\cjpeg.obj"
	-@erase "$(INTDIR)\rdppm.obj"
	-@erase "$(INTDIR)\rdgif.obj"
	-@erase "$(INTDIR)\rdtarga.obj"
	-@erase "$(INTDIR)\rdrle.obj"
	-@erase "$(INTDIR)\rdbmp.obj"
	-@erase "$(INTDIR)\rdswitch.obj"
	-@erase "$(INTDIR)\cdjpeg.obj"
	-@erase "$(OUTDIR)\cjpeg.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /YX /c
# ADD CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /YX /c
CPP_PROJ=/nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE"\
 /Fp"$(INTDIR)/cjpeg.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\cjpeg\Release/
CPP_SBRS=.\.
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/cjpeg.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 Release\jpeg.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
LINK32_FLAGS=Release\jpeg.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib\
 odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)/cjpeg.pdb" /machine:I386 /out:"$(OUTDIR)/cjpeg.exe" 
LINK32_OBJS= \
	"$(INTDIR)\cjpeg.obj" \
	"$(INTDIR)\rdppm.obj" \
	"$(INTDIR)\rdgif.obj" \
	"$(INTDIR)\rdtarga.obj" \
	"$(INTDIR)\rdrle.obj" \
	"$(INTDIR)\rdbmp.obj" \
	"$(INTDIR)\rdswitch.obj" \
	"$(INTDIR)\cdjpeg.obj" \


"$(OUTDIR)\cjpeg.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "djpeg - Win32"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "djpeg\Release"
# PROP BASE Intermediate_Dir "djpeg\Release"
# PROP BASE Target_Dir "djpeg"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "djpeg\Release"
# PROP Intermediate_Dir "djpeg\Release"
# PROP Target_Dir "djpeg"
OUTDIR=.\djpeg\Release
INTDIR=.\djpeg\Release

ALL : "$(OUTDIR)\djpeg.exe"

CLEAN : 
	-@erase "$(INTDIR)\djpeg.obj"
	-@erase "$(INTDIR)\wrppm.obj"
	-@erase "$(INTDIR)\wrgif.obj"
	-@erase "$(INTDIR)\wrtarga.obj"
	-@erase "$(INTDIR)\wrrle.obj"
	-@erase "$(INTDIR)\wrbmp.obj"
	-@erase "$(INTDIR)\rdcolmap.obj"
	-@erase "$(INTDIR)\cdjpeg.obj"
	-@erase "$(OUTDIR)\djpeg.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /YX /c
# ADD CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /YX /c
CPP_PROJ=/nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE"\
 /Fp"$(INTDIR)/djpeg.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\djpeg\Release/
CPP_SBRS=.\.
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/djpeg.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 Release\jpeg.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
LINK32_FLAGS=Release\jpeg.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib\
 odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)/djpeg.pdb" /machine:I386 /out:"$(OUTDIR)/djpeg.exe" 
LINK32_OBJS= \
	"$(INTDIR)\djpeg.obj" \
	"$(INTDIR)\wrppm.obj" \
	"$(INTDIR)\wrgif.obj" \
	"$(INTDIR)\wrtarga.obj" \
	"$(INTDIR)\wrrle.obj" \
	"$(INTDIR)\wrbmp.obj" \
	"$(INTDIR)\rdcolmap.obj" \
	"$(INTDIR)\cdjpeg.obj" \


"$(OUTDIR)\djpeg.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "jpegtran - Win32"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "jpegtran\Release"
# PROP BASE Intermediate_Dir "jpegtran\Release"
# PROP BASE Target_Dir "jpegtran"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "jpegtran\Release"
# PROP Intermediate_Dir "jpegtran\Release"
# PROP Target_Dir "jpegtran"
OUTDIR=.\jpegtran\Release
INTDIR=.\jpegtran\Release

ALL : "$(OUTDIR)\jpegtran.exe"

CLEAN : 
	-@erase "$(INTDIR)\jpegtran.obj"
	-@erase "$(INTDIR)\rdswitch.obj"
	-@erase "$(INTDIR)\cdjpeg.obj"
	-@erase "$(INTDIR)\transupp.obj"
	-@erase "$(OUTDIR)\jpegtran.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /YX /c
# ADD CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /YX /c
CPP_PROJ=/nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE"\
 /Fp"$(INTDIR)/jpegtran.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\jpegtran\Release/
CPP_SBRS=.\.
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/jpegtran.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 Release\jpeg.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
LINK32_FLAGS=Release\jpeg.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib\
 odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)/jpegtran.pdb" /machine:I386 /out:"$(OUTDIR)/jpegtran.exe" 
LINK32_OBJS= \
	"$(INTDIR)\jpegtran.obj" \
	"$(INTDIR)\rdswitch.obj" \
	"$(INTDIR)\cdjpeg.obj" \
	"$(INTDIR)\transupp.obj" \


"$(OUTDIR)\jpegtran.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "rdjpgcom - Win32"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "rdjpgcom\Release"
# PROP BASE Intermediate_Dir "rdjpgcom\Release"
# PROP BASE Target_Dir "rdjpgcom"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "rdjpgcom\Release"
# PROP Intermediate_Dir "rdjpgcom\Release"
# PROP Target_Dir "rdjpgcom"
OUTDIR=.\rdjpgcom\Release
INTDIR=.\rdjpgcom\Release

ALL : "$(OUTDIR)\rdjpgcom.exe"

CLEAN : 
	-@erase "$(INTDIR)\rdjpgcom.obj"
	-@erase "$(OUTDIR)\rdjpgcom.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /YX /c
# ADD CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /YX /c
CPP_PROJ=/nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE"\
 /Fp"$(INTDIR)/rdjpgcom.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\rdjpgcom\Release/
CPP_SBRS=.\.
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/rdjpgcom.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 Release\jpeg.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
LINK32_FLAGS=Release\jpeg.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib\
 odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)/rdjpgcom.pdb" /machine:I386 /out:"$(OUTDIR)/rdjpgcom.exe" 
LINK32_OBJS= \
	"$(INTDIR)\rdjpgcom.obj"

"$(OUTDIR)\rdjpgcom.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "wrjpgcom - Win32"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "wrjpgcom\Release"
# PROP BASE Intermediate_Dir "wrjpgcom\Release"
# PROP BASE Target_Dir "wrjpgcom"
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "wrjpgcom\Release"
# PROP Intermediate_Dir "wrjpgcom\Release"
# PROP Target_Dir "wrjpgcom"
OUTDIR=.\wrjpgcom\Release
INTDIR=.\wrjpgcom\Release

ALL : "$(OUTDIR)\wrjpgcom.exe"

CLEAN : 
	-@erase "$(INTDIR)\wrjpgcom.obj"
	-@erase "$(OUTDIR)\wrjpgcom.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /YX /c
# ADD CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /YX /c
CPP_PROJ=/nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE"\
 /Fp"$(INTDIR)/wrjpgcom.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\wrjpgcom\Release/
CPP_SBRS=.\.
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/wrjpgcom.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 Release\jpeg.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
LINK32_FLAGS=Release\jpeg.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib\
 odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)/wrjpgcom.pdb" /machine:I386 /out:"$(OUTDIR)/wrjpgcom.exe" 
LINK32_OBJS= \
	"$(INTDIR)\wrjpgcom.obj"

"$(OUTDIR)\wrjpgcom.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 

.c{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.c{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

################################################################################
# Begin Target

# Name "cjpeg - Win32"

!IF  "$(CFG)" == "cjpeg - Win32"

!ENDIF 

################################################################################
# Begin Source File

SOURCE="cjpeg.c"
DEP_CPP_CJPEG=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	"jversion.h"\
	

"$(INTDIR)\cjpeg.obj" : $(SOURCE) $(DEP_CPP_CJPEG) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="cdjpeg.c"
DEP_CPP_CDJPE=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	

"$(INTDIR)\cdjpeg.obj" : $(SOURCE) $(DEP_CPP_CDJPE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="rdswitch.c"
DEP_CPP_RDSWI=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	

"$(INTDIR)\rdswitch.obj" : $(SOURCE) $(DEP_CPP_RDSWI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="rdppm.c"
DEP_CPP_RDPPM=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	

"$(INTDIR)\rdppm.obj" : $(SOURCE) $(DEP_CPP_RDPPM) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="rdgif.c"
DEP_CPP_RDGIF=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	

"$(INTDIR)\rdgif.obj" : $(SOURCE) $(DEP_CPP_RDGIF) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="rdtarga.c"
DEP_CPP_RDTAR=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	

"$(INTDIR)\rdtarga.obj" : $(SOURCE) $(DEP_CPP_RDTAR) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="rdbmp.c"
DEP_CPP_RDBMP=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	

"$(INTDIR)\rdbmp.obj" : $(SOURCE) $(DEP_CPP_RDBMP) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="rdrle.c"
DEP_CPP_RDRLE=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	

"$(INTDIR)\rdrle.obj" : $(SOURCE) $(DEP_CPP_RDRLE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
# End Target
################################################################################
# Begin Target

# Name "djpeg - Win32"

!IF  "$(CFG)" == "djpeg - Win32"

!ENDIF 

################################################################################
# Begin Source File

SOURCE="djpeg.c"
DEP_CPP_DJPEG=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	"jversion.h"\
	

"$(INTDIR)\djpeg.obj" : $(SOURCE) $(DEP_CPP_DJPEG) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="cdjpeg.c"
DEP_CPP_CDJPE=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	

"$(INTDIR)\cdjpeg.obj" : $(SOURCE) $(DEP_CPP_CDJPE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="rdcolmap.c"
DEP_CPP_RDCOL=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	

"$(INTDIR)\rdcolmap.obj" : $(SOURCE) $(DEP_CPP_RDCOL) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="wrppm.c"
DEP_CPP_WRPPM=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	

"$(INTDIR)\wrppm.obj" : $(SOURCE) $(DEP_CPP_WRPPM) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="wrgif.c"
DEP_CPP_WRGIF=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	

"$(INTDIR)\wrgif.obj" : $(SOURCE) $(DEP_CPP_WRGIF) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="wrtarga.c"
DEP_CPP_WRTAR=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	

"$(INTDIR)\wrtarga.obj" : $(SOURCE) $(DEP_CPP_WRTAR) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="wrbmp.c"
DEP_CPP_WRBMP=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	

"$(INTDIR)\wrbmp.obj" : $(SOURCE) $(DEP_CPP_WRBMP) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="wrrle.c"
DEP_CPP_WRRLE=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	

"$(INTDIR)\wrrle.obj" : $(SOURCE) $(DEP_CPP_WRRLE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
# End Target
################################################################################
# Begin Target

# Name "jpegtran - Win32"

!IF  "$(CFG)" == "jpegtran - Win32"

!ENDIF 

################################################################################
# Begin Source File

SOURCE="jpegtran.c"
DEP_CPP_JPEGT=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	"transupp.h"\
	"jversion.h"\
	

"$(INTDIR)\jpegtran.obj" : $(SOURCE) $(DEP_CPP_JPEGT) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="cdjpeg.c"
DEP_CPP_CDJPE=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	

"$(INTDIR)\cdjpeg.obj" : $(SOURCE) $(DEP_CPP_CDJPE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="rdswitch.c"
DEP_CPP_RDSWI=\
	"cdjpeg.h"\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jerror.h"\
	"cderror.h"\
	

"$(INTDIR)\rdswitch.obj" : $(SOURCE) $(DEP_CPP_RDSWI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="transupp.c"
DEP_CPP_TRANS=\
	"jinclude.h"\
	"jconfig.h"\
	"jpeglib.h"\
	"jmorecfg.h"\
	"jpegint.h"\
	"jerror.h"\
	"transupp.h"\
	

"$(INTDIR)\transupp.obj" : $(SOURCE) $(DEP_CPP_TRANS) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
# End Target
################################################################################
# Begin Target

# Name "rdjpgcom - Win32"

!IF  "$(CFG)" == "rdjpgcom - Win32"

!ENDIF 

################################################################################
# Begin Source File

SOURCE="rdjpgcom.c"
DEP_CPP_RDJPG=\
	"jinclude.h"\
	"jconfig.h"\
	

"$(INTDIR)\rdjpgcom.obj" : $(SOURCE) $(DEP_CPP_RDJPG) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
# End Target
################################################################################
# Begin Target

# Name "wrjpgcom - Win32"

!IF  "$(CFG)" == "wrjpgcom - Win32"

!ENDIF 

################################################################################
# Begin Source File

SOURCE="wrjpgcom.c"
DEP_CPP_WRJPG=\
	"jinclude.h"\
	"jconfig.h"\
	

"$(INTDIR)\wrjpgcom.obj" : $(SOURCE) $(DEP_CPP_WRJPG) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
# End Target
# End Project
################################################################################

