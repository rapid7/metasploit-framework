#!/bin/sh

set -e

#OSSL=openssl-0.9.8o
OSSL=openssl-0.9.8n

cd $OSSL

cat Configure | grep -v 'linux-msf' | sed -e 's#my %table=(#my %table=(\
"linux-msf", "gcc:\\$\\${MSF_CFLAGS} -DL_ENDIAN -DTERMIO -Wall::\\$\\${MSF_CFLAGS} -D_REENTRANT::\\$\\${MSF_CFLAGS} -ldl:BN_LLONG ${x86_gcc_des} ${x86_gcc_opts}:${x86_elf_asm}:dlfcn:linux-shared:\\$\\${MSF_CFLAGS} -fPIC::.so.\\$(SHLIB_MAJOR).\\$(SHLIB_MINOR)",\
#;' > Configure-msf
mv Configure-msf Configure
chmod +x Configure

./Configure --prefix=/tmp/out threads shared no-hw no-dlfcn no-zlib no-krb5 no-idea 386 linux-msf
cd ..


# These have to be relative to PWD because the OpenSSL make system builds in
# multiple different levels of subdirs, so we can't just use ../../
export LIBC=${PWD}/../bionic/libc
export LIBM=${PWD}/../bionic/libm
export COMPILED=${PWD}/../bionic/compiled

export MSF_CFLAGS="-Os -Wl,--hash-style=sysv -march=i386 -nostdinc -nostdlib -fno-builtin -fpic -I ${LIBC}/include -I ${LIBC}/kernel/common/linux/ -I ${LIBC}/kernel/common/ -I ${LIBC}/arch-x86/include/ -I ${LIBC}/kernel/arch-x86/  -I${LIBC}/private -I${LIBM}/include -DPIC -Dwchar_t='char' -D_SIZE_T_DECLARED -DElf_Size='u_int32_t' -D_BYTE_ORDER=_LITTLE_ENDIAN -L${COMPILED} -lc"

# We don't need all the random executable utilities that 'all' builds, just the
# important .so files
#make -C $OSSL depend clean all

make -C $OSSL depend clean build_libs


