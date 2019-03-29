#
# XXX: NOTE: this will only compile the x86 version.
#
# To compile the x64 version, use:
# C:\> call "c:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\vcvarsall.bat" amd64
# C:\> cl.exe -LD /Zl /GS- /DBUILDMODE=2 /link /entry:DllMain kernel32.lib
#

if [ -z "$PREFIX" ]; then
  PREFIX=i686-w64-mingw32 
fi

rm -f *.o *.dll
$PREFIX-gcc -c template.c
$PREFIX-windres -o rc.o template.rc
$PREFIX-gcc -mdll -o junk.tmp -Wl,--base-file,base.tmp template.o rc.o
rm -f junk.tmp
$PREFIX-dlltool --dllname template_x86_windows.dll --base-file base.tmp --output-exp temp.exp #--def template.def
rm -f base.tmp
$PREFIX-gcc -mdll -o template_x86_windows.dll template.o rc.o -Wl,temp.exp
rm -f temp.exp

$PREFIX-strip template_x86_windows.dll
rm -f *.o
