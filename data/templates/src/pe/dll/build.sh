if [ -z "$PREFIX" ]; then
  PREFIX=i586-mingw32msvc
fi

rm -f *.o *.dll
$PREFIX-gcc -c template.c
$PREFIX-windres -o rc.o template.rc
$PREFIX-gcc -mdll -o junk.tmp -Wl,--base-file,base.tmp template.o rc.o
rm -f junk.tmp
$PREFIX-dlltool --dllname template.dll --base-file base.tmp --output-exp temp.exp --def template.def
rm -f base.tmp
$PREFIX-gcc -mdll -o template.dll template.o rc.o -Wl,temp.exp
rm -f temp.exp

$PREFIX-strip template.dll
rm -f *.o
