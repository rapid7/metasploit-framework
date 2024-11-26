#!/bin/bash

# Assume x86_64 Ubuntu 16.04 base system
apt-get install build-essential \
  gcc-5-multilib \
  gcc-5-multilib-arm-linux-gnueabi \
  gcc-5-multilib-arm-linux-gnueabihf \
  gcc-5-multilib-mips-linux-gnu \
  gcc-5-multilib-mips64-linux-gnuabi64 \
  gcc-5-multilib-mips64el-linux-gnuabi64 \
  gcc-5-multilib-mipsel-linux-gnu \
  gcc-5-multilib-powerpc-linux-gnu \
  gcc-5-multilib-powerpc64-linux-gnu \
  gcc-5-multilib-s390x-linux-gnu \
  gcc-5-multilib-sparc64-linux-gnu \
  gcc-4.9-powerpc64le-linux-gnu \
  gcc-4.9-aarch64-linux-gnu

if [ ! -e /usr/include/asm ];
  then ln -sf /usr/include/asm-generic /usr/include/asm
fi
