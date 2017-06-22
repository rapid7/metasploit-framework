#!/bin/bash

build () {
  CC=$1
  TARGET_SUFFIX=$2
  CFLAGS=$3

  echo "[*] Building for ${TARGET_SUFFIX}..."
  for type in {shellcode,system,findsock}
   do ${CC} ${CFLAGS} -Wall -Werror -fPIC -fno-stack-protector samba-root-${type}.c -shared -o samba-root-${type}-${TARGET_SUFFIX}.so
  done
}

rm -f *.o *.so *.gz

#
# Linux GLIBC
#

# x86
build "gcc" "linux-glibc-x86_64" "-m64 -D OLD_LIB_SET_2"
build "gcc" "linux-glibc-x86" "-m32 -D OLD_LIB_SET_1"

# ARM
build "arm-linux-gnueabi-gcc-5" "linux-glibc-armel" "-march=armv5 -mlittle-endian"
build "arm-linux-gnueabihf-gcc-5" "linux-glibc-armhf" "-march=armv7 -mlittle-endian"
build "aarch64-linux-gnu-gcc-4.9" "linux-glibc-aarch64" ""

# MIPS
build "mips-linux-gnu-gcc-5" "linux-glibc-mips" "-D OLD_LIB_SET_1"
build "mipsel-linux-gnu-gcc-5"  "linux-glibc-mipsel" "-D OLD_LIB_SET_1"
build "mips64-linux-gnuabi64-gcc-5"  "linux-glibc-mips64" "-D OLD_LIB_SET_1"
build "mips64el-linux-gnuabi64-gcc-5" "linux-glibc-mips64el" "-D OLD_LIB_SET_1"

# SPARC
build "sparc64-linux-gnu-gcc-5" "linux-glibc-sparc64" ""
build "sparc64-linux-gnu-gcc-5" "linux-glibc-sparc" "-m32 -D OLD_LIB_SET_1"

# PowerPC
build "powerpc-linux-gnu-gcc-5" "linux-glibc-powerpc" "-D OLD_LIB_SET_1"
build "powerpc64-linux-gnu-gcc-5" "linux-glibc-powerpc64" ""
build "powerpc64le-linux-gnu-gcc-4.9" "linux-glibc-powerpc64le" ""

# S390X
build "s390x-linux-gnu-gcc-5" "linux-glibc-s390x" ""

gzip -9 *.so
rm -f *.o *.so
