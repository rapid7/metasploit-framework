# Makefile for KiTrap0d->NtVdmControl() exploit.
#   - Tavis Ormandy <taviso@sdf.lonestar.org>

CFLAGS=/Zi /Zp /Od /TC /nologo

all: vdmallowed.exe vdmexploit.dll

clean:
	rm -f *.obj *.exe *.dll *.pdb *.ilk *.exp *.lib

vdmallowed.exe: vdmallowed.obj
	cl /Fe$(@F) $(**)

vdmexploit.dll: vdmexploit.obj
	cl /Fe$(@F) /LD $(**)

