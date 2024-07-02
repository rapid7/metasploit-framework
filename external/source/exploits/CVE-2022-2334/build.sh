#!/bin/sh
CCx64="x86_64-w64-mingw32"

${CCx64}-gcc -shared -o temp.dll template.def template.c
${CCx64}-strip -s temp.dll -o ../../../../data/exploits/CVE-2022-2334/template_x64_windows.dll
rm -f temp.dll *.o
chmod -x ../../../../data/exploits/CVE-2022-2334/template_x64_windows.dll
