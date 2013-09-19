#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'

module Metasm
class ELF < ExeFormat
  MAGIC = "\x7fELF"	# 0x7f454c46
  CLASS = { 0 => 'NONE', 1 => '32', 2 => '64', 200 => '64_icc' }
  DATA  = { 0 => 'NONE', 1 => 'LSB', 2 => 'MSB' }
  VERSION = { 0 => 'INVALID', 1 => 'CURRENT' }
  ABI = { 0 => 'SYSV', 1 => 'HPUX', 2 => 'NETBSD', 3 => 'LINUX',
    6 => 'SOLARIS', 7 => 'AIX', 8 => 'IRIX', 9 => 'FREEBSD',
    10 => 'TRU64', 11 => 'MODESTO', 12 => 'OPENBSD', 97 => 'ARM',
    255 => 'STANDALONE'}
  TYPE = { 0 => 'NONE', 1 => 'REL', 2 => 'EXEC', 3 => 'DYN', 4 => 'CORE' }
  TYPE_LOPROC = 0xff00
  TYPE_HIPROC = 0xffff

  MACHINE = {
     0 => 'NONE',   1 => 'M32',     2 => 'SPARC',   3 => '386',
     4 => '68K',    5 => '88K',     6 => '486',     7 => '860',
     8 => 'MIPS',   9 => 'S370',   10 => 'MIPS_RS3_LE',
    15 => 'PARISC',
    17 => 'VPP500',18 => 'SPARC32PLUS', 19 => '960',
    20 => 'PPC',   21 => 'PPC64',  22 => 'S390',
    36 => 'V800',  37 => 'FR20',   38 => 'RH32',   39 => 'MCORE',
    40 => 'ARM',   41 => 'ALPHA_STD', 42 => 'SH', 43 => 'SPARCV9',
    44 => 'TRICORE', 45 => 'ARC',  46 => 'H8_300', 47 => 'H8_300H',
    48 => 'H8S',   49 => 'H8_500', 50 => 'IA_64',  51 => 'MIPS_X',
    52 => 'COLDFIRE', 53 => '68HC12', 54 => 'MMA', 55 => 'PCP',
    56 => 'NCPU',  57 => 'NDR1',   58 => 'STARCORE', 59 => 'ME16',
    60 => 'ST100', 61 => 'TINYJ',  62 => 'X86_64', 63 => 'PDSP',
    66 => 'FX66',  67 => 'ST9PLUS',
    68 => 'ST7',   69 => '68HC16', 70 => '68HC11', 71 => '68HC08',
    72 => '68HC05',73 => 'SVX',    74 => 'ST19',   75 => 'VAX',
    76 => 'CRIS',  77 => 'JAVELIN',78 => 'FIREPATH', 79 => 'ZSP',
    80 => 'MMIX',  81 => 'HUANY',  82 => 'PRISM',  83 => 'AVR',
    84 => 'FR30',  85 => 'D10V',   86 => 'D30V',   87 => 'V850',
    88 => 'M32R',  89 => 'MN10300',90 => 'MN10200',91 => 'PJ',
    92 => 'OPENRISC', 93 => 'ARC_A5', 94 => 'XTENSA',
    99 => 'PJ',
    0x9026 => 'ALPHA'
  }

  FLAGS = {
    'SPARC' => {0x100 => '32PLUS', 0x200 => 'SUN_US1',
      0x400 => 'HAL_R1', 0x800 => 'SUN_US3',
      0x8000_0000 => 'LEDATA'},
    'SPARCV9' => {0 => 'TSO', 1 => 'PSO', 2 => 'RMO'},	# XXX not a flag
    'MIPS' => {1 => 'NOREORDER', 2 => 'PIC', 4 => 'CPIC',
      8 => 'XGOT', 16 => '64BIT_WHIRL', 32 => 'ABI2',
      64 => 'ABI_ON32'}
  }

  DYNAMIC_TAG = { 0 => 'NULL', 1 => 'NEEDED', 2 => 'PLTRELSZ', 3 =>
    'PLTGOT', 4 => 'HASH', 5 => 'STRTAB', 6 => 'SYMTAB', 7 => 'RELA',
    8 => 'RELASZ', 9 => 'RELAENT', 10 => 'STRSZ', 11 => 'SYMENT',
    12 => 'INIT', 13 => 'FINI', 14 => 'SONAME', 15 => 'RPATH',
    16 => 'SYMBOLIC', 17 => 'REL', 18 => 'RELSZ', 19 => 'RELENT',
    20 => 'PLTREL', 21 => 'DEBUG', 22 => 'TEXTREL', 23 => 'JMPREL',
    24 => 'BIND_NOW',
    25 => 'INIT_ARRAY', 26 => 'FINI_ARRAY',
    27 => 'INIT_ARRAYSZ', 28 => 'FINI_ARRAYSZ',
    29 => 'RUNPATH', 30 => 'FLAGS', 31 => 'ENCODING',
    32 => 'PREINIT_ARRAY', 33 => 'PREINIT_ARRAYSZ',
    0x6fff_fdf5 => 'GNU_PRELINKED',
    0x6fff_fdf6 => 'GNU_CONFLICTSZ', 0x6fff_fdf7 => 'LIBLISTSZ',
    0x6fff_fdf8 => 'CHECKSUM',       0x6fff_fdf9 => 'PLTPADSZ',
    0x6fff_fdfa => 'MOVEENT',        0x6fff_fdfb => 'MOVESZ',
    0x6fff_fdfc => 'FEATURE_1',      0x6fff_fdfd => 'POSFLAG_1',
    0x6fff_fdfe => 'SYMINSZ',        0x6fff_fdff => 'SYMINENT',
    0x6fff_fef5 => 'GNU_HASH',
    0x6fff_fef6 => 'TLSDESC_PLT',    0x6fff_fef7 => 'TLSDESC_GOT',
    0x6fff_fef8 => 'GNU_CONFLICT',   0x6fff_fef9 => 'GNU_LIBLIST',
    0x6fff_fefa => 'CONFIG',         0x6fff_fefb => 'DEPAUDIT',
    0x6fff_fefc => 'AUDIT',          0x6fff_fefd => 'PLTPAD',
    0x6fff_fefe => 'MOVETAB',        0x6fff_feff => 'SYMINFO',
    0x6fff_fff0 => 'VERSYM',         0x6fff_fff9 => 'RELACOUNT',
    0x6fff_fffa => 'RELCOUNT',       0x6fff_fffb => 'FLAGS_1',
    0x6fff_fffc => 'VERDEF',         0x6fff_fffd => 'VERDEFNUM',
    0x6fff_fffe => 'VERNEED',        0x6fff_ffff => 'VERNEEDNUM'
  }
  DYNAMIC_TAG_LOPROC = 0x7000_0000
  DYNAMIC_TAG_HIPROC = 0x7fff_ffff

  # for tags between DT_LOPROC and DT_HIPROC, use DT_PROC[header.machine][tag-DT_LOPROC]
  DYNAMIC_TAG_PROC = {
    'MIPS' => {
      1 => 'RLD_VERSION', 2 => 'TIME_STAMP', 3 => 'ICHECKSUM',
      4 => 'IVERSION', 5 => 'M_FLAGS', 6 => 'BASE_ADDRESS', 7 => 'MSYM',
      8 => 'CONFLICT', 9 => 'LIBLIST', 0x0a => 'LOCAL_GOTNO',
      0x0b => 'CONFLICTNO', 0x10 => 'LIBLISTNO', 0x11 => 'SYMTABNO',
      0x12 => 'UNREFEXTNO', 0x13 => 'GOTSYM', 0x14 => 'HIPAGENO',
      0x16 => 'RLD_MAP', 0x17 => 'DELTA_CLASS', 0x18 => 'DELTA_CLASS_NO',
      0x19 => 'DELTA_INSTANCE', 0x1a => 'DELTA_INSTANCE_NO',
      0x1b => 'DELTA_RELOC', 0x1c => 'DELTA_RELOC_NO', 0x1d => 'DELTA_SYM',
      0x1e => 'DELTA_SYM_NO', 0x20 => 'DELTA_CLASSSYM', 0x21 => 'DELTA_CLASSSYM_NO',
      0x22 => 'CXX_FLAGS', 0x23 => 'PIXIE_INIT', 0x24 => 'SYMBOL_LIB',
      0x25 => 'LOCALPAGE_GOTIDX', 0x26 => 'LOCAL_GOTIDX',
      0x27 => 'HIDDEN_GOTIDX', 0x28 => 'PROTECTED_GOTIDX',
      0x29 => 'OPTIONS', 0x2a => 'INTERFACE', 0x2b => 'DYNSTR_ALIGN',
      0x2c => 'INTERFACE_SIZE', 0x2d => 'RLD_TEXT_RESOLVE_ADDR',
      0x2e => 'PERF_SUFFIX', 0x2f => 'COMPACT_SIZE',
      0x30 => 'GP_VALUE', 0x31 => 'AUX_DYNAMIC',
    }
  }


  DYNAMIC_FLAGS = { 1 => 'ORIGIN', 2 => 'SYMBOLIC', 4 => 'TEXTREL',
    8 => 'BIND_NOW', 0x10 => 'STATIC_TLS' }
  DYNAMIC_FLAGS_1 = { 1 => 'NOW', 2 => 'GLOBAL', 4 => 'GROUP',
    8 => 'NODELETE', 0x10 => 'LOADFLTR', 0x20 => 'INITFIRST',
    0x40 => 'NOOPEN', 0x80 => 'ORIGIN', 0x100 => 'DIRECT',
    0x200 => 'TRANS', 0x400 => 'INTERPOSE', 0x800 => 'NODEFLIB',
    0x1000 => 'NODUMP', 0x2000 => 'CONFALT', 0x4000 => 'ENDFILTEE',
    0x8000 => 'DISPRELDNE', 0x10000 => 'DISPRELPND' }
  DYNAMIC_FEATURE_1 = { 1 => 'PARINIT', 2 => 'CONFEXP' }
  DYNAMIC_POSFLAG_1 = { 1 => 'LAZYLOAD', 2 => 'GROUPPERM' }

  PH_TYPE = { 0 => 'NULL', 1 => 'LOAD', 2 => 'DYNAMIC', 3 => 'INTERP',
    4 => 'NOTE', 5 => 'SHLIB', 6 => 'PHDR', 7 => 'TLS',
    0x6474e550 => 'GNU_EH_FRAME', 0x6474e551 => 'GNU_STACK',
    0x6474e552 => 'GNU_RELRO' }
  PH_TYPE_LOPROC = 0x7000_0000
  PH_TYPE_HIPROC = 0x7fff_ffff
  PH_FLAGS = { 1 => 'X', 2 => 'W', 4 => 'R' }

  SH_TYPE = { 0 => 'NULL', 1 => 'PROGBITS', 2 => 'SYMTAB', 3 => 'STRTAB',
    4 => 'RELA', 5 => 'HASH', 6 => 'DYNAMIC', 7 => 'NOTE',
    8 => 'NOBITS', 9 => 'REL', 10 => 'SHLIB', 11 => 'DYNSYM',
    14 => 'INIT_ARRAY', 15 => 'FINI_ARRAY', 16 => 'PREINIT_ARRAY',
    17 => 'GROUP', 18 => 'SYMTAB_SHNDX',
    0x6fff_fff6 => 'GNU_HASH', 0x6fff_fff7 => 'GNU_LIBLIST',
    0x6fff_fff8 => 'GNU_CHECKSUM',
    0x6fff_fffd => 'GNU_verdef', 0x6fff_fffe => 'GNU_verneed',
    0x6fff_ffff => 'GNU_versym' }
  SH_TYPE_LOOS   = 0x6000_0000
  SH_TYPE_HIOS   = 0x6fff_ffff
  SH_TYPE_LOPROC = 0x7000_0000
  SH_TYPE_HIPROC = 0x7fff_ffff
  SH_TYPE_LOUSER = 0x8000_0000
  SH_TYPE_HIUSER = 0xffff_ffff

  SH_FLAGS = { 1 => 'WRITE', 2 => 'ALLOC', 4 => 'EXECINSTR',
    0x10 => 'MERGE', 0x20 => 'STRINGS', 0x40 => 'INFO_LINK',
    0x80 => 'LINK_ORDER', 0x100 => 'OS_NONCONFORMING',
    0x200 => 'GROUP', 0x400 => 'TLS' }
  SH_FLAGS_MASKPROC = 0xf000_0000

  SH_INDEX = { 0 => 'UNDEF',
    0xfff1 => 'ABS', 0xfff2 => 'COMMON',
    0xffff => 'XINDEX', }
  SH_INDEX_LORESERVE = 0xff00
  SH_INDEX_LOPROC    = 0xff00
  SH_INDEX_HIPROC    = 0xff1f
  SH_INDEX_LOOS      = 0xff20
  SH_INDEX_HIOS      = 0xff3f
  SH_INDEX_HIRESERVE = 0xffff

  SYMBOL_BIND = { 0 => 'LOCAL', 1 => 'GLOBAL', 2 => 'WEAK' }
  SYMBOL_BIND_LOPROC = 13
  SYMBOL_BIND_HIPROC = 15

  SYMBOL_TYPE = { 0 => 'NOTYPE', 1 => 'OBJECT', 2 => 'FUNC',
    3 => 'SECTION', 4 => 'FILE', 5 => 'COMMON', 6 => 'TLS' }
  SYMBOL_TYPE_LOPROC = 13
  SYMBOL_TYPE_HIPROC = 15

  SYMBOL_VISIBILITY = { 0 => 'DEFAULT', 1 => 'INTERNAL', 2 => 'HIDDEN', 3 => 'PROTECTED' }

  RELOCATION_TYPE = {	# key are in MACHINE.values
    '386' => { 0 => 'NONE', 1 => '32', 2 => 'PC32', 3 => 'GOT32',
      4 => 'PLT32', 5 => 'COPY', 6 => 'GLOB_DAT',
      7 => 'JMP_SLOT', 8 => 'RELATIVE', 9 => 'GOTOFF',
      10 => 'GOTPC', 11 => '32PLT', 12 => 'TLS_GD_PLT',
      13 => 'TLS_LDM_PLT', 14 => 'TLS_TPOFF', 15 => 'TLS_IE',
      16 => 'TLS_GOTIE', 17 => 'TLS_LE', 18 => 'TLS_GD',
      19 => 'TLS_LDM', 20 => '16', 21 => 'PC16', 22 => '8',
      23 => 'PC8', 24 => 'TLS_GD_32', 25 => 'TLS_GD_PUSH',
      26 => 'TLS_GD_CALL', 27 => 'TLS_GD_POP',
      28 => 'TLS_LDM_32', 29 => 'TLS_LDM_PUSH',
      30 => 'TLS_LDM_CALL', 31 => 'TLS_LDM_POP',
      32 => 'TLS_LDO_32', 33 => 'TLS_IE_32',
      34 => 'TLS_LE_32', 35 => 'TLS_DTPMOD32',
      36 => 'TLS_DTPOFF32', 37 => 'TLS_TPOFF32' },
    'ARM' => { 0 => 'NONE', 1 => 'PC24', 2 => 'ABS32', 3 => 'REL32',
      4 => 'PC13', 5 => 'ABS16', 6 => 'ABS12',
      7 => 'THM_ABS5', 8 => 'ABS8', 9 => 'SBREL32',
      10 => 'THM_PC22', 11 => 'THM_PC8', 12 => 'AMP_VCALL9',
      13 => 'SWI24', 14 => 'THM_SWI8', 15 => 'XPC25',
      16 => 'THM_XPC22', 20 => 'COPY', 21 => 'GLOB_DAT',
      22 => 'JUMP_SLOT', 23 => 'RELATIVE', 24 => 'GOTOFF',
      25 => 'GOTPC', 26 => 'GOT32', 27 => 'PLT32',
      100 => 'GNU_VTENTRY', 101 => 'GNU_VTINHERIT',
      250 => 'RSBREL32', 251 => 'THM_RPC22', 252 => 'RREL32',
      253 => 'RABS32', 254 => 'RPC24', 255 => 'RBASE' },
    'IA_64' => { 0 => 'NONE',
      0x21 => 'IMM14', 0x22 => 'IMM22', 0x23 => 'IMM64',
      0x24 => 'DIR32MSB', 0x25 => 'DIR32LSB',
      0x26 => 'DIR64MSB', 0x27 => 'DIR64LSB',
      0x2a => 'GPREL22', 0x2b => 'GPREL64I',
      0x2c => 'GPREL32MSB', 0x2d => 'GPREL32LSB',
      0x2e => 'GPREL64MSB', 0x2f => 'GPREL64LSB',
      0x32 => 'LTOFF22', 0x33 => 'LTOFF64I',
      0x3a => 'PLTOFF22', 0x3b => 'PLTOFF64I',
      0x3e => 'PLTOFF64MSB', 0x3f => 'PLTOFF64LSB',
      0x43 => 'FPTR64I', 0x44 => 'FPTR32MSB',
      0x45 => 'FPTR32LSB', 0x46 => 'FPTR64MSB',
      0x47 => 'FPTR64LSB',
      0x48 => 'PCREL60B', 0x49 => 'PCREL21B',
      0x4a => 'PCREL21M', 0x4b => 'PCREL21F',
      0x4c => 'PCREL32MSB', 0x4d => 'PCREL32LSB',
      0x4e => 'PCREL64MSB', 0x4f => 'PCREL64LSB',
      0x52 => 'LTOFF_FPTR22', 0x53 => 'LTOFF_FPTR64I',
      0x54 => 'LTOFF_FPTR32MSB', 0x55 => 'LTOFF_FPTR32LSB',
      0x56 => 'LTOFF_FPTR64MSB', 0x57 => 'LTOFF_FPTR64LSB',
      0x5c => 'SEGREL32MSB', 0x5d => 'SEGREL32LSB',
      0x5e => 'SEGREL64MSB', 0x5f => 'SEGREL64LSB',
      0x64 => 'SECREL32MSB', 0x65 => 'SECREL32LSB',
      0x66 => 'SECREL64MSB', 0x67 => 'SECREL64LSB',
      0x6c => 'REL32MSB', 0x6d => 'REL32LSB',
      0x6e => 'REL64MSB', 0x6f => 'REL64LSB',
      0x74 => 'LTV32MSB', 0x75 => 'LTV32LSB',
      0x76 => 'LTV64MSB', 0x77 => 'LTV64LSB',
      0x79 => 'PCREL21BI', 0x7a => 'PCREL22',
      0x7b => 'PCREL64I', 0x80 => 'IPLTMSB',
      0x81 => 'IPLTLSB', 0x85 => 'SUB',
      0x86 => 'LTOFF22X', 0x87 => 'LDXMOV',
      0x91 => 'TPREL14', 0x92 => 'TPREL22',
      0x93 => 'TPREL64I', 0x96 => 'TPREL64MSB',
      0x97 => 'TPREL64LSB', 0x9a => 'LTOFF_TPREL22',
      0xa6 => 'DTPMOD64MSB', 0xa7 => 'DTPMOD64LSB',
      0xaa => 'LTOFF_DTPMOD22', 0xb1 => 'DTPREL14',
      0xb2 => 'DTPREL22', 0xb3 => 'DTPREL64I',
      0xb4 => 'DTPREL32MSB', 0xb5 => 'DTPREL32LSB',
      0xb6 => 'DTPREL64MSB', 0xb7 => 'DTPREL64LSB',
      0xba => 'LTOFF_DTPREL22' },
    'M32' => { 0 => 'NONE', 1 => '32', 2 => '32_S', 3 => 'PC32_S',
      4 => 'GOT32_S', 5 => 'PLT32_S', 6 => 'COPY',
      7 => 'GLOB_DAT', 8 => 'JMP_SLOT', 9 => 'RELATIVE',
      10 => 'RELATIVE_S' },
    'MIPS' => {
      0 => 'NONE', 1 => '16', 2 => '32', 3 => 'REL32',
      4 => '26', 5 => 'HI16', 6 => 'LO16', 7 => 'GPREL16',
      8 => 'LITERAL', 9 => 'GOT16', 10 => 'PC16',
      11 => 'CALL16', 12 => 'GPREL32',
      16 => 'SHIFT5', 17 => 'SHIFT6', 18 => '64',
      19 => 'GOT_DISP', 20 => 'GOT_PAGE', 21 => 'GOT_OFST',
      22 => 'GOT_HI16', 23 => 'GOT_LO16', 24 => 'SUB',
      25 => 'INSERT_A', 26 => 'INSERT_B', 27 => 'DELETE',
      28 => 'HIGHER', 29 => 'HIGHEST', 30 => 'CALL_HI16',
      31 => 'CALL_LO16', 32 => 'SCN_DISP', 33 => 'REL16',
      34 => 'ADD_IMMEDIATE', 35 => 'PJUMP', 36 => 'RELGOT',
      37 => 'JALR', 38 => 'TLS_DTPMOD32', 39 => 'TLS_DTPREL32',
      40 => 'TLS_DTPMOD64', 41 => 'TLS_DTPREL64',
      42 => 'TLS_GD', 43 => 'TLS_LDM', 44 => 'TLS_DTPREL_HI16',
      45 => 'TLS_DTPREL_LO16', 46 => 'TLS_GOTTPREL',
      47 => 'TLS_TPREL32', 48 => 'TLS_TPREL64',
      49 => 'TLS_TPREL_HI16', 50 => 'TLS_TPREL_LO16',
      51 => 'GLOB_DAT', 52 => 'NUM' },
    'PPC' => { 0 => 'NONE',
      1 => 'ADDR32', 2 => 'ADDR24', 3 => 'ADDR16',
      4 => 'ADDR16_LO', 5 => 'ADDR16_HI', 6 => 'ADDR16_HA',
      7 => 'ADDR14', 8 => 'ADDR14_BRTAKEN', 9 => 'ADDR14_BRNTAKEN',
      10 => 'REL24', 11 => 'REL14',
      12 => 'REL14_BRTAKEN', 13 => 'REL14_BRNTAKEN',
      14 => 'GOT16', 15 => 'GOT16_LO',
      16 => 'GOT16_HI', 17 => 'GOT16_HA',
      18 => 'PLTREL24', 19 => 'COPY',
      20 => 'GLOB_DAT', 21 => 'JMP_SLOT',
      22 => 'RELATIVE', 23 => 'LOCAL24PC',
      24 => 'UADDR32', 25 => 'UADDR16',
      26 => 'REL32', 27 => 'PLT32',
      28 => 'PLTREL32', 29 => 'PLT16_LO',
      30 => 'PLT16_HI', 31 => 'PLT16_HA',
      32 => 'SDAREL16', 33 => 'SECTOFF',
      34 => 'SECTOFF_LO', 35 => 'SECTOFF_HI',
      36 => 'SECTOFF_HA', 67 => 'TLS',
      68 => 'DTPMOD32', 69 => 'TPREL16',
      70 => 'TPREL16_LO', 71 => 'TPREL16_HI',
      72 => 'TPREL16_HA', 73 => 'TPREL32',
      74 => 'DTPREL16', 75 => 'DTPREL16_LO',
      76 => 'DTPREL16_HI', 77 => 'DTPREL16_HA',
      78 => 'DTPREL32', 79 => 'GOT_TLSGD16',
      80 => 'GOT_TLSGD16_LO', 81 => 'GOT_TLSGD16_HI',
      82 => 'GOT_TLSGD16_HA', 83 => 'GOT_TLSLD16',
      84 => 'GOT_TLSLD16_LO', 85 => 'GOT_TLSLD16_HI',
      86 => 'GOT_TLSLD16_HA', 87 => 'GOT_TPREL16',
      88 => 'GOT_TPREL16_LO', 89 => 'GOT_TPREL16_HI',
      90 => 'GOT_TPREL16_HA', 101 => 'EMB_NADDR32',
      102 => 'EMB_NADDR16', 103 => 'EMB_NADDR16_LO',
      104 => 'EMB_NADDR16_HI', 105 => 'EMB_NADDR16_HA',
      106 => 'EMB_SDAI16', 107 => 'EMB_SDA2I16',
      108 => 'EMB_SDA2REL', 109 => 'EMB_SDA21',
      110 => 'EMB_MRKREF', 111 => 'EMB_RELSEC16',
      112 => 'EMB_RELST_LO', 113 => 'EMB_RELST_HI',
      114 => 'EMB_RELST_HA', 115 => 'EMB_BIT_FLD',
      116 => 'EMB_RELSDA' },
    'SPARC' => { 0 => 'NONE', 1 => '8', 2 => '16', 3 => '32',
      4 => 'DISP8', 5 => 'DISP16', 6 => 'DISP32',
      7 => 'WDISP30', 8 => 'WDISP22', 9 => 'HI22',
      10 => '22', 11 => '13', 12 => 'LO10', 13 => 'GOT10',
      14 => 'GOT13', 15 => 'GOT22', 16 => 'PC10',
      17 => 'PC22', 18 => 'WPLT30', 19 => 'COPY',
      20 => 'GLOB_DAT', 21 => 'JMP_SLOT', 22 => 'RELATIVE',
      23 => 'UA32', 24 => 'PLT32', 25 => 'HIPLT22',
      26 => 'LOPLT10', 27 => 'PCPLT32', 28 => 'PCPLT22',
      29 => 'PCPLT10', 30 => '10', 31 => '11', 32 => '64',
      33 => 'OLO10', 34 => 'HH22', 35 => 'HM10', 36 => 'LM22',
      37 => 'PC_HH22', 38 => 'PC_HM10', 39 => 'PC_LM22',
      40 => 'WDISP16', 41 => 'WDISP19', 42 => 'GLOB_JMP',
      43 => '7', 44 => '5', 45 => '6', 46 => 'DISP64',
      47 => 'PLT64', 48 => 'HIX22', 49 => 'LOX10', 50 => 'H44',
      51 => 'M44', 52 => 'L44', 53 => 'REGISTER', 54 => 'UA64',
      55 => 'UA16', 56 => 'TLS_GD_HI22', 57 => 'TLS_GD_LO10',
      58 => 'TLS_GD_ADD', 59 => 'TLS_GD_CALL',
      60 => 'TLS_LDM_HI22', 61 => 'TLS_LDM_LO10',
      62 => 'TLS_LDM_ADD', 63 => 'TLS_LDM_CALL',
      64 => 'TLS_LDO_HIX22', 65 => 'TLS_LDO_LOX10',
      66 => 'TLS_LDO_ADD', 67 => 'TLS_IE_HI22',
      68 => 'TLS_IE_LO10', 69 => 'TLS_IE_LD',
      70 => 'TLS_IE_LDX', 71 => 'TLS_IE_ADD',
      72 => 'TLS_LE_HIX22', 73 => 'TLS_LE_LOX10',
      74 => 'TLS_DTPMOD32', 75 => 'TLS_DTPMOD64',
      76 => 'TLS_DTPOFF32', 77 => 'TLS_DTPOFF64',
      78 => 'TLS_TPOFF32', 79 => 'TLS_TPOFF64' },
    'X86_64' => { 0 => 'NONE',
      1 => '64', 2 => 'PC32', 3 => 'GOT32', 4 => 'PLT32',
      5 => 'COPY', 6 => 'GLOB_DAT', 7 => 'JMP_SLOT',
      8 => 'RELATIVE', 9 => 'GOTPCREL', 10 => '32',
      11 => '32S', 12 => '16', 13 => 'PC16', 14 => '8',
      15 => 'PC8', 16 => 'DTPMOD64', 17 => 'DTPOFF64',
      18 => 'TPOFF64', 19 => 'TLSGD', 20 => 'TLSLD',
      21 => 'DTPOFF32', 22 => 'GOTTPOFF', 23 => 'TPOFF32' }
  }

  DEFAULT_INTERP = '/lib/ld-linux.so.2'
  DEFAULT_INTERP64 = '/lib64/ld-linux-x86-64.so.2'

  class SerialStruct < Metasm::SerialStruct
    new_int_field :addr, :off, :xword, :sword, :sxword
  end

  class Header < SerialStruct
    mem :magic, 4, MAGIC
    byte :e_class, 0, CLASS
    byte :data, 0, DATA
    byte :i_version, 'CURRENT', VERSION
    byte :abi, 0, ABI
    byte :abi_version
    mem :ident_unk, 7
    half :type, 0, TYPE
    half :machine, 0, MACHINE
    word :version, 'CURRENT', VERSION
    addr :entry
    off :phoff
    off :shoff
    word :flags
    fld_bits(:flags) { |elf, hdr| FLAGS[hdr.machine] || {} }
    halfs :ehsize, :phentsize, :phnum, :shentsize, :shnum, :shstrndx

    def self.size elf
      x = elf.bitsize >> 3
      40 + 3*x
    end
  end

  class Segment < SerialStruct
    attr_accessor :type, :offset, :vaddr, :paddr, :filesz, :memsz, :flags, :align
    attr_accessor :encoded

    def struct_specialized(elf)
      return Segment32 if not elf
      case elf.bitsize
      when 32; Segment32
      else Segment64
      end
    end

    def self.size elf
      x = elf.bitsize >> 3
      8 + 6*x
    end
  end

  class Segment32 < Segment
    word :type, 0, PH_TYPE
    off :offset
    addr :vaddr
    addr :paddr
    xword :filesz
    xword :memsz
    word :flags ; fld_bits :flags, PH_FLAGS
    xword :align
  end
  class Segment64 < Segment
    word :type, 0, PH_TYPE
    word :flags ; fld_bits :flags, PH_FLAGS
    off :offset
    addr :vaddr
    addr :paddr
    xword :filesz
    xword :memsz
    xword :align
  end

  class Section < SerialStruct
    word :name_p
    word :type, 0, SH_TYPE
    xword :flags ; fld_bits :flags, SH_FLAGS
    addr :addr
    off :offset
    xword :size
    word :link
    word :info
    xword :addralign
    xword :entsize

    attr_accessor :name, :encoded

    def self.size elf
      x = elf.bitsize >> 3
      16 + 6*x
    end
  end

  class Symbol < SerialStruct
    def struct_specialized(elf)
      return Symbol32 if not elf
      case elf.bitsize
      when 32; Symbol32
      else Symbol64
      end
    end

    attr_accessor :name_p, :value, :size, :bind, :type, :other, :shndx
    attr_accessor :name, :thunk

    def self.size elf
      x = elf.bitsize >> 3
      8 + 2*x
    end
  end

  class Symbol32 < Symbol
    word :name_p
    addr :value
    xword :size
    bitfield :byte, 0 => :type, 4 => :bind
    fld_enum :type, SYMBOL_TYPE
    fld_enum :bind, SYMBOL_BIND
    byte :other
    half :shndx, 0, SH_INDEX
  end
  class Symbol64 < Symbol
    word :name_p
    bitfield :byte, 0 => :type, 4 => :bind
    fld_enum :type, SYMBOL_TYPE
    fld_enum :bind, SYMBOL_BIND
    byte :other
    half :shndx, 0, SH_INDEX
    addr :value
    xword :size
  end

  class Relocation < SerialStruct
    attr_accessor :offset, :type, :symbol
    def struct_specialized(elf)
      return Relocation32 if not elf
      case elf.bitsize
      when 32; Relocation32
      else Relocation64
      end
    end

    def addend ; end

    def self.size elf
      x = elf.bitsize >> 3
      2*x
    end

  end
  class Relocation32 < Relocation
    addr :offset
    bitfield :xword, 0 => :type, 8 => :symbol
    fld_enum(:type) { |elf, rel| RELOCATION_TYPE[elf.header.machine] || {} }
    fld_enum(:symbol) { |elf, rel| elf.symbols }
  end
  class Relocation64 < Relocation
    addr :offset
    bitfield :xword, 0 => :type, 32 => :symbol
    fld_enum(:type) { |elf, rel| RELOCATION_TYPE[elf.header.machine] || {} }
    fld_enum(:symbol) { |elf, rel| elf.symbols }
  end
  class RelocationAddend < Relocation
    attr_accessor :addend
    def struct_specialized(elf)
      return RelocationAddend32 if not elf
      case elf.bitsize
      when 32; RelocationAddend32
      else RelocationAddend64
      end
    end
    def self.size elf
      x = elf.bitsize >> 3
      3*x
    end

  end
  class RelocationAddend32 < RelocationAddend
    addr :offset
    bitfield :xword, 0 => :type, 8 => :symbol
    fld_enum(:type) { |elf, rel| RELOCATION_TYPE[elf.header.machine] || {} }
    fld_enum(:symbol) { |elf, rel| elf.symbols }
    sxword :addend
  end
  class RelocationAddend64 < RelocationAddend
    addr :offset
    bitfield :xword, 0 => :type, 32 => :symbol
    fld_enum(:type) { |elf, rel| RELOCATION_TYPE[elf.header.machine] || {} }
    fld_enum(:symbol) { |elf, rel| elf.symbols }
    sxword :addend
  end

  class SerialStruct
    new_int_field :leb
  end

  # libdwarf/dwarf.h
  DWARF_TAG = {
    0x01 => 'ARRAY_TYPE', 0x02 => 'CLASS_TYPE', 0x03 => 'ENTRY_POINT',
    0x04 => 'ENUMERATION_TYPE', 0x05 => 'FORMAL_PARAMETER',
    0x08 => 'IMPORTED_DECLARATION', 0x0a => 'LABEL', 0x0b => 'LEXICAL_BLOCK',
    0x0d => 'MEMBER', 0x0f => 'POINTER_TYPE',
    0x10 => 'REFERENCE_TYPE', 0x11 => 'COMPILE_UNIT', 0x12 => 'STRING_TYPE', 0x13 => 'STRUCTURE_TYPE',
    0x15 => 'SUBROUTINE_TYPE', 0x16 => 'TYPEDEF', 0x17 => 'UNION_TYPE',
    0x18 => 'UNSPECIFIED_PARAMETERS', 0x19 => 'VARIANT', 0x1a => 'COMMON_BLOCK', 0x1b => 'COMMON_INCLUSION',
    0x1c => 'INHERITANCE', 0x1d => 'INLINED_SUBROUTINE', 0x1e => 'MODULE', 0x1f => 'PTR_TO_MEMBER_TYPE',
    0x20 => 'SET_TYPE', 0x21 => 'SUBRANGE_TYPE', 0x22 => 'WITH_STMT', 0x23 => 'ACCESS_DECLARATION',
    0x24 => 'BASE_TYPE', 0x25 => 'CATCH_BLOCK', 0x26 => 'CONST_TYPE', 0x27 => 'CONSTANT',
    0x28 => 'ENUMERATOR', 0x29 => 'FILE_TYPE', 0x2a => 'FRIEND', 0x2b => 'NAMELIST',
    0x2c => 'NAMELIST_ITEM', 0x2d => 'PACKED_TYPE', 0x2e => 'SUBPROGRAM', 0x2f => 'TEMPLATE_TYPE_PARAM',
    0x30 => 'TEMPLATE_VALUE_PARAM', 0x31 => 'THROWN_TYPE', 0x32 => 'TRY_BLOCK', 0x33 => 'VARIANT_PART',
    0x34 => 'VARIABLE', 0x35 => 'VOLATILE_TYPE',
  }
  DWARF_FORM = {
    0x01 => 'ADDR', 0x03 => 'BLOCK2',
    0x04 => 'BLOCK4', 0x05 => 'DATA2', 0x06 => 'DATA4', 0x07 => 'DATA8',
    0x08 => 'STRING', 0x09 => 'BLOCK', 0x0a => 'BLOCK1', 0x0b => 'DATA1',
    0x0c => 'FLAG', 0x0d => 'SDATA', 0x0e => 'STRP', 0x0f => 'UDATA',
    0x10 => 'REF_ADDR', 0x11 => 'REF1', 0x12 => 'REF2', 0x13 => 'REF4',
    0x14 => 'REF8', 0x15 => 'REF_UDATA', 0x16 => 'INDIRECT',
  }
  DWARF_AT = {
    0x01 => 'SIBLING', 0x02 => 'LOCATION', 0x03 => 'NAME',
    0x09 => 'ORDERING', 0x0a => 'SUBSCR_DATA', 0x0b => 'BYTE_SIZE',
    0x0c => 'BIT_OFFSET', 0x0d => 'BIT_SIZE', 0x0f => 'ELEMENT_LIST',
    0x10 => 'STMT_LIST', 0x11 => 'LOW_PC', 0x12 => 'HIGH_PC', 0x13 => 'LANGUAGE',
    0x14 => 'MEMBER', 0x15 => 'DISCR', 0x16 => 'DISCR_VALUE', 0x17 => 'VISIBILITY',
    0x18 => 'IMPORT', 0x19 => 'STRING_LENGTH', 0x1a => 'COMMON_REFERENCE', 0x1b => 'COMP_DIR',
    0x1c => 'CONST_VALUE', 0x1d => 'CONTAINING_TYPE', 0x1e => 'DEFAULT_VALUE',
    0x20 => 'INLINE', 0x21 => 'IS_OPTIONAL', 0x22 => 'LOWER_BOUND',
    0x25 => 'PRODUCER', 0x27 => 'PROTOTYPED',
    0x2a => 'RETURN_ADDR',
    0x2c => 'START_SCOPE', 0x2e => 'STRIDE_SIZE', 0x2f => 'UPPER_BOUND',
    0x31 => 'ABSTRACT_ORIGIN', 0x32 => 'ACCESSIBILITY', 0x33 => 'ADDRESS_CLASS',
    0x34 => 'ARTIFICIAL', 0x35 => 'BASE_TYPES', 0x36 => 'CALLING_CONVENTION', 0x37 => 'COUNT',
    0x38 => 'DATA_MEMBER_LOCATION', 0x39 => 'DECL_COLUMN', 0x3a => 'DECL_FILE', 0x3b => 'DECL_LINE',
    0x3c => 'DECLARATION', 0x3d => 'DISCR_LIST', 0x3e => 'ENCODING', 0x3f => 'EXTERNAL',
    0x40 => 'FRAME_BASE', 0x41 => 'FRIEND', 0x42 => 'IDENTIFIER_CASE', 0x43 => 'MACRO_INFO',
    0x44 => 'NAMELIST_ITEM', 0x45 => 'PRIORITY', 0x46 => 'SEGMENT', 0x47 => 'SPECIFICATION',
    0x48 => 'STATIC_LINK', 0x49 => 'TYPE', 0x4a => 'USE_LOCATION', 0x4b => 'VARIABLE_PARAMETER',
    0x4c => 'VIRTUALITY', 0x4d => 'VTABLE_ELEM_LOCATION',
  }

  class DwarfDebug < SerialStruct
    class Node < SerialStruct
      leb :index
      leb :tag, 0, DWARF_TAG
      byte :has_child
      attr_accessor :parent, :children, :attributes
      class Attribute < SerialStruct
        leb :attr, 0, DWARF_AT
        leb :form, 0, DWARF_FORM
        attr_accessor :data
        def to_s(a); "#{@attr}=(#@form)#{dump(@data, a)}" end
      end
    end

    word :cu_len
    half :version, 2
    word :abbrev_off
    byte :ptr_sz
    attr_accessor :tree	# ary of root siblings (Node)
  end

  def self.hash_symbol_name(name)
    name.unpack('C*').inject(0) { |hash, char|
      break hash if char == 0
      hash <<= 4
      hash += char
      hash ^= (hash >> 24) & 0xf0
      hash &= 0x0fff_ffff
    }
  end

  def self.gnu_hash_symbol_name(name)
    name.unpack('C*').inject(5381) { |hash, char|
      break hash if char == 0
      (hash*33 + char) & 0xffff_ffff
    }
  end

  attr_accessor :header, :segments, :sections, :tag, :symbols, :relocations, :endianness, :bitsize, :debug
  def initialize(cpu=nil)
    @header = Header.new
    @tag = {}
    @symbols = [Symbol32.new]
     @symbols.first.shndx = 'UNDEF'
    @relocations = []
    @sections = [Section.new]
     @sections.first.type = 'NULL'
    @segments = []
    if cpu
      @endianness = cpu.endianness
      @bitsize = cpu.size
    else
      @endianness = :little
      @bitsize = 32
    end
    super(cpu)
  end

  def shortname; 'elf'; end
end

class LoadedELF < ELF
  attr_accessor :load_address
  def addr_to_off(addr)
    @load_address ||= 0
    addr >= @load_address ? addr - @load_address : addr if addr
  end
end

class FatELF < ExeFormat
  MAGIC = "\xfa\x70\x0e\x1f"	# 0xfat..elf

  class SerialStruct < Metasm::SerialStruct
    new_int_field :qword
  end

  class Header < SerialStruct
    mem :magic, 4, MAGIC
    word :version, 1
    byte :nfat_arch
    byte :reserved

    def decode(fe)
      super(fe)
      raise InvalidExeFormat, "Invalid FatELF signature #{@magic.unpack('H*').first.inspect}" if @magic != MAGIC
    end

    def set_default_values(fe)
      @nfat_arch ||= fe.list.length
      super(fe)
    end
  end
  class FatArch < SerialStruct
    word :machine
    bytes :abi, :abi_version, :e_class, :data, :res1, :res2
    qwords :offset, :size

    fld_enum :machine, ELF::MACHINE
    fld_enum :abi, ELF::ABI
    fld_enum :e_class, ELF::CLASS
    fld_enum :data, ELF::DATA

    attr_accessor :encoded
  end

  def encode_byte(val)         Expression[val].encode(:u8,  @endianness) end
  def encode_word(val)         Expression[val].encode(:u16, @endianness) end
  def encode_qword(val)        Expression[val].encode(:u64, @endianness) end
  def decode_byte(edata = @encoded)  edata.decode_imm(:u8,  @endianness) end
  def decode_word(edata = @encoded)  edata.decode_imm(:u16, @endianness) end
  def decode_qword(edata = @encoded) edata.decode_imm(:u64, @endianness) end

  attr_accessor :header, :list
  def initialize
    @endianness = :little
    @list = []
    super()
  end

  def decode
    @header = Header.decode(self)
    @list = []
    @header.nfat_arch.times { @list << FatArch.decode(self) }
    @list.each { |e|
      e.encoded = @encoded[e.offset, e.size] || EncodedData.new
    }
  end

  def encode
    @header ||= Header.new
    @encoded = @header.encode(self)
    @list.map! { |f|
      if f.kind_of? ExeFormat
        e = f
        f = FatArch.new
        f.encoded = e.encode_string
        h = e.header
        f.machine, f.abi, f.abi_version, f.e_class, f.data =
         h.machine, h.abi, h.abi_version, h.e_class, h.data
      end
      f.offset = new_label('fat_off')
      f.size = f.encoded.size
      @encoded << f.encode(self)
      f
    }
    bd = {}
    @list.each { |f|
      @encoded.align 4096
      bd[f.offset] = @encoded.length if f.offset.kind_of? String
      @encoded << f.encoded
    }
    @encoded.fixup! bd
  end

  def [](i) AutoExe.decode(@list[i].encoded) if @list[i] end
  def <<(exe) @list << exe ; self end

  def self.autoexe_load(*a)
    fe = super(*a)
    fe.decode
    # TODO have a global callback or whatever to prompt the user
    # which file he wants to load in the dasm
    puts "FatELF: using 1st archive member" if $VERBOSE
    fe[0]
  end

  def shortname; 'fatelf'; end
end
end

require 'metasm/exe_format/elf_encode'
require 'metasm/exe_format/elf_decode'

# TODO symbol version info
__END__
/*
 * Version structures.  There are three types of version structure:
 *
 *  o	A definition of the versions within the image itself.
 *	Each version definition is assigned a unique index (starting from
 *	VER_NDX_BGNDEF)	which is used to cross-reference symbols associated to
 *	the version.  Each version can have one or more dependencies on other
 *	version definitions within the image.  The version name, and any
 *	dependency names, are specified in the version definition auxiliary
 *	array.  Version definition entries require a version symbol index table.
 *
 *  o	A version requirement on a needed dependency.  Each needed entry
 *	specifies the shared object dependency (as specified in DT_NEEDED).
 *	One or more versions required from this dependency are specified in the
 *	version needed auxiliary array.
 *
 *  o	A version symbol index table.  Each symbol indexes into this array
 *	to determine its version index.  Index values of VER_NDX_BGNDEF or
 *	greater indicate the version definition to which a symbol is associated.
 *	(the size of a symbol index entry is recorded in the sh_info field).
 */
#ifndef	_ASM

typedef struct {			/* Version Definition Structure. */
  Elf32_Half	vd_version;	/* this structures version revision */
  Elf32_Half	vd_flags;	/* version information */
  Elf32_Half	vd_ndx;		/* version index */
  Elf32_Half	vd_cnt;		/* no. of associated aux entries */
  Elf32_Word	vd_hash;	/* version name hash value */
  Elf32_Word	vd_aux;		/* no. of bytes from start of this */
          /*	verdef to verdaux array */
  Elf32_Word	vd_next;	/* no. of bytes from start of this */
} Elf32_Verdef;				/*	verdef to next verdef entry */

typedef struct {			/* Verdef Auxiliary Structure. */
  Elf32_Word	vda_name;	/* first element defines the version */
          /*	name. Additional entries */
          /*	define dependency names. */
  Elf32_Word	vda_next;	/* no. of bytes from start of this */
} Elf32_Verdaux;			/*	verdaux to next verdaux entry */


typedef	struct {			/* Version Requirement Structure. */
  Elf32_Half	vn_version;	/* this structures version revision */
  Elf32_Half	vn_cnt;		/* no. of associated aux entries */
  Elf32_Word	vn_file;	/* name of needed dependency (file) */
  Elf32_Word	vn_aux;		/* no. of bytes from start of this */
          /*	verneed to vernaux array */
  Elf32_Word	vn_next;	/* no. of bytes from start of this */
} Elf32_Verneed;			/*	verneed to next verneed entry */

typedef struct {			/* Verneed Auxiliary Structure. */
  Elf32_Word	vna_hash;	/* version name hash value */
  Elf32_Half	vna_flags;	/* version information */
  Elf32_Half	vna_other;
  Elf32_Word	vna_name;	/* version name */
  Elf32_Word	vna_next;	/* no. of bytes from start of this */
} Elf32_Vernaux;			/*	vernaux to next vernaux entry */

typedef	Elf32_Half 	Elf32_Versym;	/* Version symbol index array */

typedef struct {
  Elf32_Half	si_boundto;	/* direct bindings - symbol bound to */
  Elf32_Half	si_flags;	/* per symbol flags */
} Elf32_Syminfo;


#if (defined(_LP64) || ((__STDC__ - 0 == 0) && (!defined(_NO_LONGLONG))))
typedef struct {
  Elf64_Half	vd_version;	/* this structures version revision */
  Elf64_Half	vd_flags;	/* version information */
  Elf64_Half	vd_ndx;		/* version index */
  Elf64_Half	vd_cnt;		/* no. of associated aux entries */
  Elf64_Word	vd_hash;	/* version name hash value */
  Elf64_Word	vd_aux;		/* no. of bytes from start of this */
          /*	verdef to verdaux array */
  Elf64_Word	vd_next;	/* no. of bytes from start of this */
} Elf64_Verdef;				/*	verdef to next verdef entry */

typedef struct {
  Elf64_Word	vda_name;	/* first element defines the version */
          /*	name. Additional entries */
          /*	define dependency names. */
  Elf64_Word	vda_next;	/* no. of bytes from start of this */
} Elf64_Verdaux;			/*	verdaux to next verdaux entry */

typedef struct {
  Elf64_Half	vn_version;	/* this structures version revision */
  Elf64_Half	vn_cnt;		/* no. of associated aux entries */
  Elf64_Word	vn_file;	/* name of needed dependency (file) */
  Elf64_Word	vn_aux;		/* no. of bytes from start of this */
          /*	verneed to vernaux array */
  Elf64_Word	vn_next;	/* no. of bytes from start of this */
} Elf64_Verneed;			/*	verneed to next verneed entry */

typedef struct {
  Elf64_Word	vna_hash;	/* version name hash value */
  Elf64_Half	vna_flags;	/* version information */
  Elf64_Half	vna_other;
  Elf64_Word	vna_name;	/* version name */
  Elf64_Word	vna_next;	/* no. of bytes from start of this */
} Elf64_Vernaux;			/*	vernaux to next vernaux entry */

typedef	Elf64_Half	Elf64_Versym;

typedef struct {
  Elf64_Half	si_boundto;	/* direct bindings - symbol bound to */
  Elf64_Half	si_flags;	/* per symbol flags */
} Elf64_Syminfo;
#endif	/* (defined(_LP64) || ((__STDC__ - 0 == 0) ... */

#endif

/*
 * Versym symbol index values.  Values greater than VER_NDX_GLOBAL
 * and less then VER_NDX_LORESERVE associate symbols with user
 * specified version descriptors.
 */
#define	VER_NDX_LOCAL		0	/* symbol is local */
#define	VER_NDX_GLOBAL		1	/* symbol is global and assigned to */
          /*	the base version */
#define	VER_NDX_LORESERVE	0xff00	/* beginning of RESERVED entries */
#define	VER_NDX_ELIMINATE	0xff01	/* symbol is to be eliminated */

/*
 * Verdef and Verneed (via Veraux) flags values.
 */
#define	VER_FLG_BASE		0x1	/* version definition of file itself */
#define	VER_FLG_WEAK		0x2	/* weak version identifier */

/*
 * Verdef version values.
 */
#define	VER_DEF_NONE		0	/* Ver_def version */
#define	VER_DEF_CURRENT		1
#define	VER_DEF_NUM		2

/*
 * Verneed version values.
 */
#define	VER_NEED_NONE		0	/* Ver_need version */
#define	VER_NEED_CURRENT	1
#define	VER_NEED_NUM		2


/*
 * Syminfo flag values
 */
#define	SYMINFO_FLG_DIRECT	0x0001	/* direct bound symbol */
#define	SYMINFO_FLG_PASSTHRU	0x0002	/* pass-thru symbol for translator */
#define	SYMINFO_FLG_COPY	0x0004	/* symbol is a copy-reloc */
#define	SYMINFO_FLG_LAZYLOAD	0x0008	/* symbol bound to object to be lazy */
          /*	loaded */

/*
 * key values for Syminfo.si_boundto
 */
#define	SYMINFO_BT_SELF		0xffff	/* symbol bound to self */
#define	SYMINFO_BT_PARENT	0xfffe	/* symbol bound to parent */
#define	SYMINFO_BT_LOWRESERVE	0xff00	/* beginning of reserved entries */

/*
 * Syminfo version values.
 */
#define	SYMINFO_NONE		0	/* Syminfo version */
#define	SYMINFO_CURRENT		1
#define	SYMINFO_NUM		2

