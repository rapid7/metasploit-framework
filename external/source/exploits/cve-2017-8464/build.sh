#!/bin/sh
rm -f *.o *.dll

CCx86="i686-w64-mingw32"
CCx64="x86_64-w64-mingw32"

${CCx64}-gcc -m64 -c -Os template.c -Wall -shared
${CCx64}-dllwrap -m64 --def template.def *.o -o temp.dll
${CCx64}-strip -s temp.dll -o ../../../../data/exploits/cve-2017-8464/template_x64_windows.dll
rm -f temp.dll *.o
chmod -x ../../../../data/exploits/cve-2017-8464/template_x64_windows.dll

${CCx86}-gcc -c -Os template.c -Wall -shared
${CCx86}-dllwrap --def template.def *.o -o temp.dll
${CCx86}-strip -s temp.dll -o ../../../../data/exploits/cve-2017-8464/template_x86_windows.dll
rm -f temp.dll *.o
chmod -x ../../../../data/exploits/cve-2017-8464/template_x86_windows.dll
