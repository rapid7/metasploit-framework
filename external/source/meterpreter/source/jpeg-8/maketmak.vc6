# Microsoft Developer Studio Generated NMAKE File, Based on jpegtran.dsp
!IF "$(CFG)" == ""
CFG=jpegtran - Win32
!MESSAGE Keine Konfiguration angegeben. jpegtran - Win32 wird als Standard verwendet.
!ENDIF 

!IF "$(CFG)" != "jpegtran - Win32"
!MESSAGE UngÅltige Konfiguration "$(CFG)" angegeben.
!MESSAGE Sie kînnen beim AusfÅhren von NMAKE eine Konfiguration angeben
!MESSAGE durch Definieren des Makros CFG in der Befehlszeile. Zum Beispiel:
!MESSAGE 
!MESSAGE NMAKE /f "jpegtran.mak" CFG="jpegtran - Win32"
!MESSAGE 
!MESSAGE FÅr die Konfiguration stehen zur Auswahl:
!MESSAGE 
!MESSAGE "jpegtran - Win32" (basierend auf  "Win32 (x86) Console Application")
!MESSAGE 
!ERROR Eine ungÅltige Konfiguration wurde angegeben.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe
RSC=rc.exe
OUTDIR=.\jpegtran\Release
INTDIR=.\jpegtran\Release
# Begin Custom Macros
OutDir=.\jpegtran\Release
# End Custom Macros

ALL : "$(OUTDIR)\jpegtran.exe"


CLEAN :
	-@erase "$(INTDIR)\cdjpeg.obj"
	-@erase "$(INTDIR)\jpegtran.obj"
	-@erase "$(INTDIR)\rdswitch.obj"
	-@erase "$(INTDIR)\transupp.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\jpegtran.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\jpegtran.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=Release\jpeg.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\jpegtran.pdb" /machine:I386 /out:"$(OUTDIR)\jpegtran.exe" 
LINK32_OBJS= \
	"$(INTDIR)\cdjpeg.obj" \
	"$(INTDIR)\jpegtran.obj" \
	"$(INTDIR)\rdswitch.obj" \
	"$(INTDIR)\transupp.obj"

"$(OUTDIR)\jpegtran.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

CPP_PROJ=/nologo /G6 /MT /W3 /GX /Ox /Oa /Ob2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /Fp"$(INTDIR)\jpegtran.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("jpegtran.dep")
!INCLUDE "jpegtran.dep"
!ELSE 
!MESSAGE Warning: cannot find "jpegtran.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "jpegtran - Win32"
SOURCE=.\cdjpeg.c

"$(INTDIR)\cdjpeg.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\jpegtran.c

"$(INTDIR)\jpegtran.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\rdswitch.c

"$(INTDIR)\rdswitch.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\transupp.c

"$(INTDIR)\transupp.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

