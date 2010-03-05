# Microsoft Developer Studio Generated NMAKE File, Based on cjpeg.dsp
!IF "$(CFG)" == ""
CFG=cjpeg - Win32
!MESSAGE Keine Konfiguration angegeben. cjpeg - Win32 wird als Standard verwendet.
!ENDIF 

!IF "$(CFG)" != "cjpeg - Win32"
!MESSAGE UngÅltige Konfiguration "$(CFG)" angegeben.
!MESSAGE Sie kînnen beim AusfÅhren von NMAKE eine Konfiguration angeben
!MESSAGE durch Definieren des Makros CFG in der Befehlszeile. Zum Beispiel:
!MESSAGE 
!MESSAGE NMAKE /f "cjpeg.mak" CFG="cjpeg - Win32"
!MESSAGE 
!MESSAGE FÅr die Konfiguration stehen zur Auswahl:
!MESSAGE 
!MESSAGE "cjpeg - Win32" (basierend auf  "Win32 (x86) Console Application")
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
OUTDIR=.\cjpeg\Release
INTDIR=.\cjpeg\Release
# Begin Custom Macros
OutDir=.\cjpeg\Release
# End Custom Macros

ALL : "$(OUTDIR)\cjpeg.exe"


CLEAN :
	-@erase "$(INTDIR)\cdjpeg.obj"
	-@erase "$(INTDIR)\cjpeg.obj"
	-@erase "$(INTDIR)\rdbmp.obj"
	-@erase "$(INTDIR)\rdgif.obj"
	-@erase "$(INTDIR)\rdppm.obj"
	-@erase "$(INTDIR)\rdrle.obj"
	-@erase "$(INTDIR)\rdswitch.obj"
	-@erase "$(INTDIR)\rdtarga.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\cjpeg.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\cjpeg.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=Release\jpeg.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\cjpeg.pdb" /machine:I386 /out:"$(OUTDIR)\cjpeg.exe" 
LINK32_OBJS= \
	"$(INTDIR)\cdjpeg.obj" \
	"$(INTDIR)\cjpeg.obj" \
	"$(INTDIR)\rdbmp.obj" \
	"$(INTDIR)\rdgif.obj" \
	"$(INTDIR)\rdppm.obj" \
	"$(INTDIR)\rdrle.obj" \
	"$(INTDIR)\rdswitch.obj" \
	"$(INTDIR)\rdtarga.obj"

"$(OUTDIR)\cjpeg.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

CPP_PROJ=/nologo /G6 /MT /W3 /GX /Ox /Oa /Ob2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /Fp"$(INTDIR)\cjpeg.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

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
!IF EXISTS("cjpeg.dep")
!INCLUDE "cjpeg.dep"
!ELSE 
!MESSAGE Warning: cannot find "cjpeg.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "cjpeg - Win32"
SOURCE=.\cdjpeg.c

"$(INTDIR)\cdjpeg.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\cjpeg.c

"$(INTDIR)\cjpeg.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\rdbmp.c

"$(INTDIR)\rdbmp.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\rdgif.c

"$(INTDIR)\rdgif.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\rdppm.c

"$(INTDIR)\rdppm.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\rdrle.c

"$(INTDIR)\rdrle.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\rdswitch.c

"$(INTDIR)\rdswitch.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\rdtarga.c

"$(INTDIR)\rdtarga.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

