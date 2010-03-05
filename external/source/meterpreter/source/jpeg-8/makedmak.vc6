# Microsoft Developer Studio Generated NMAKE File, Based on djpeg.dsp
!IF "$(CFG)" == ""
CFG=djpeg - Win32
!MESSAGE Keine Konfiguration angegeben. djpeg - Win32 wird als Standard verwendet.
!ENDIF 

!IF "$(CFG)" != "djpeg - Win32"
!MESSAGE UngÅltige Konfiguration "$(CFG)" angegeben.
!MESSAGE Sie kînnen beim AusfÅhren von NMAKE eine Konfiguration angeben
!MESSAGE durch Definieren des Makros CFG in der Befehlszeile. Zum Beispiel:
!MESSAGE 
!MESSAGE NMAKE /f "djpeg.mak" CFG="djpeg - Win32"
!MESSAGE 
!MESSAGE FÅr die Konfiguration stehen zur Auswahl:
!MESSAGE 
!MESSAGE "djpeg - Win32" (basierend auf  "Win32 (x86) Console Application")
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
OUTDIR=.\djpeg\Release
INTDIR=.\djpeg\Release
# Begin Custom Macros
OutDir=.\djpeg\Release
# End Custom Macros

ALL : "$(OUTDIR)\djpeg.exe"


CLEAN :
	-@erase "$(INTDIR)\cdjpeg.obj"
	-@erase "$(INTDIR)\djpeg.obj"
	-@erase "$(INTDIR)\rdcolmap.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\wrbmp.obj"
	-@erase "$(INTDIR)\wrgif.obj"
	-@erase "$(INTDIR)\wrppm.obj"
	-@erase "$(INTDIR)\wrrle.obj"
	-@erase "$(INTDIR)\wrtarga.obj"
	-@erase "$(OUTDIR)\djpeg.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\djpeg.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=Release\jpeg.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\djpeg.pdb" /machine:I386 /out:"$(OUTDIR)\djpeg.exe" 
LINK32_OBJS= \
	"$(INTDIR)\cdjpeg.obj" \
	"$(INTDIR)\djpeg.obj" \
	"$(INTDIR)\rdcolmap.obj" \
	"$(INTDIR)\wrbmp.obj" \
	"$(INTDIR)\wrgif.obj" \
	"$(INTDIR)\wrppm.obj" \
	"$(INTDIR)\wrrle.obj" \
	"$(INTDIR)\wrtarga.obj"

"$(OUTDIR)\djpeg.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

CPP_PROJ=/nologo /G6 /MT /W3 /GX /Ox /Oa /Ob2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /Fp"$(INTDIR)\djpeg.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

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
!IF EXISTS("djpeg.dep")
!INCLUDE "djpeg.dep"
!ELSE 
!MESSAGE Warning: cannot find "djpeg.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "djpeg - Win32"
SOURCE=.\cdjpeg.c

"$(INTDIR)\cdjpeg.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\djpeg.c

"$(INTDIR)\djpeg.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\rdcolmap.c

"$(INTDIR)\rdcolmap.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\wrbmp.c

"$(INTDIR)\wrbmp.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\wrgif.c

"$(INTDIR)\wrgif.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\wrppm.c

"$(INTDIR)\wrppm.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\wrrle.c

"$(INTDIR)\wrrle.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\wrtarga.c

"$(INTDIR)\wrtarga.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

