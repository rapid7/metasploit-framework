#!/bin/sh

gcc -o cpuinfo.ia32.bin cpuinfo.c -static -m32 -Wall && \
strip cpuinfo.ia32.bin && \
gcc -o cpuinfo.ia64.bin cpuinfo.c -static -m64 -Wall && \
strip cpuinfo.ia64.bin && \
i586-mingw32msvc-gcc -m32 -static -Wall -o cpuinfo.exe cpuinfo.c && \
strip cpuinfo.exe

ls -la cpuinfo.ia32.bin cpuinfo.ia64.bin cpuinfo.exe

