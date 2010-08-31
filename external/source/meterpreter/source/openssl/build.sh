#!/bin/sh

OSSL=openssl-0.9.8o

pushd $OSSL
./Configure threads no-zlib no-krb5 386 --prefix=/tmp/out linux-msf no-dlfcn shared
popd

export LIBC=../../bionic/libc
export LIBM=../../bionic/libm
export COMPILED=../../bionic/compiled

export CFLAGS="-I ${LIBC}/include -I ${LIBC}/kernel/common/linux/ -I ${LIBC}/kernel/common/ -I ${LIBC}/arch-x86/include/ -I ${LIBC}/kernel/arch-x86/  -I${LIBC}/private -fPIC -DPIC -nostdinc -nostdlib -Dwchar_t='char' -fno-builtin -D_SIZE_T_DECLARED -DElf_Size='u_int32_t' -I${LIBM}/include  -L${COMPILED}  -D_BYTE_ORDER=_LITTLE_ENDIAN -lc"

make -C $OSSL depend clean all
