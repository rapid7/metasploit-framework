# -*- coding: binary -*-

#
# Architecture constants
#
ARCH_ANY     = '_any_'
ARCH_X86     = 'x86'
ARCH_X86_64  = 'x86_64'
ARCH_X64     = 'x64' # To be used for compatability with ARCH_X86_64
ARCH_MIPS    = 'mips'
ARCH_MIPSLE  = 'mipsle'
ARCH_MIPSBE  = 'mipsbe'
ARCH_PPC     = 'ppc'
ARCH_PPC64   = 'ppc64'
ARCH_CBEA    = 'cbea'
ARCH_CBEA64  = 'cbea64'
ARCH_SPARC   = 'sparc'
ARCH_CMD     = 'cmd'
ARCH_PHP     = 'php'
ARCH_TTY     = 'tty'
ARCH_ARMLE   = 'armle'
ARCH_ARMBE   = 'armbe'
ARCH_JAVA    = 'java'
ARCH_RUBY    = 'ruby'
ARCH_DALVIK  = 'dalvik'
ARCH_PYTHON  = 'python'
ARCH_NODEJS  = 'nodejs'
ARCH_FIREFOX = 'firefox'
ARCH_ZARCH   = 'zarch'
ARCH_TYPES   =
  [
    ARCH_X86,
    ARCH_X86_64,
    ARCH_MIPS,
    ARCH_MIPSLE,
    ARCH_MIPSBE,
    ARCH_PPC,
    ARCH_PPC64,
    ARCH_CBEA,
    ARCH_CBEA64,
    ARCH_SPARC,
    ARCH_ARMLE,
    ARCH_ARMBE,
    ARCH_CMD,
    ARCH_PHP,
    ARCH_TTY,
    ARCH_JAVA,
    ARCH_RUBY,
    ARCH_DALVIK,
    ARCH_PYTHON,
    ARCH_NODEJS,
    ARCH_FIREFOX,
    ARCH_ZARCH,
  ]

ARCH_ALL = ARCH_TYPES

#
# Endian constants
#
ENDIAN_LITTLE = 0
ENDIAN_BIG    = 1

IS_ENDIAN_LITTLE = ( [1].pack('s') == "\x01\x00" ) ? true : false
IS_ENDIAN_BIG    = ( not IS_ENDIAN_LITTLE )
