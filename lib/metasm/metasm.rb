#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


module Metasm
  # root directory for metasm files
  # used by some scripts, eg to find samples/dasm-plugin directory
  Metasmdir = File.dirname(__FILE__)
  # add it to the ruby library path
  $: << Metasmdir

  # constants defined in the same file as another
  Const_autorequire_equiv = {
    'X86' => 'Ia32', 'PPC' => 'PowerPC',
    'X64' => 'X86_64', 'AMD64' => 'X86_64',
    'MIPS64' => 'MIPS',
    'UniversalBinary' => 'MachO', 'COFFArchive' => 'COFF',
    'DEY' => 'DEX',
    'PTrace' => 'LinOS', 'FatELF' => 'ELF',
    'LoadedELF' => 'ELF', 'LoadedPE' => 'PE',
    'LoadedAutoExe' => 'AutoExe',
    'LinuxRemoteString' => 'LinOS',
    'LinDebugger' => 'LinOS',
    'WinAPI' => 'WinOS',
    'WindowsRemoteString' => 'WinOS', 'WinDbgAPI' => 'WinOS',
    'WinDebugger' => 'WinOS',
    'GdbRemoteString' => 'GdbClient', 'GdbRemoteDebugger' => 'GdbClient',
    'DecodedInstruction' => 'Disassembler', 'DecodedFunction' => 'Disassembler',
    'InstructionBlock' => 'Disassembler',
  }

  # files to require to get the definition of those constants
  Const_autorequire = {
    'Ia32' => 'cpu/ia32', 'MIPS' => 'cpu/mips', 'PowerPC' => 'cpu/ppc', 'ARM' => 'cpu/arm',
    'X86_64' => 'cpu/x86_64', 'Sh4' => 'cpu/sh4', 'Dalvik' => 'cpu/dalvik', 'ARC' => 'cpu/arc',
    'Python' => 'cpu/python', 'Z80' => 'cpu/z80', 'CY16' => 'cpu/cy16', 'BPF' => 'cpu/bpf',
    'C' => 'compile_c',
    'MZ' => 'exe_format/mz', 'PE' => 'exe_format/pe',
    'ELF' => 'exe_format/elf', 'COFF' => 'exe_format/coff',
    'Shellcode' => 'exe_format/shellcode', 'AutoExe' => 'exe_format/autoexe',
    'AOut' => 'exe_format/a_out', 'MachO' => 'exe_format/macho',
    'DEX' => 'exe_format/dex',
    'NDS' => 'exe_format/nds', 'XCoff' => 'exe_format/xcoff',
    'GameBoyRom' => 'exe_format/gb',
    'Bflt' => 'exe_format/bflt', 'Dol' => 'exe_format/dol',
    'PYC' => 'exe_format/pyc', 'JavaClass' => 'exe_format/javaclass',
    'SWF' => 'exe_format/swf', 'ZIP' => 'exe_format/zip',
    'Shellcode_RWX' => 'exe_format/shellcode_rwx',
    'Gui' => 'gui',
    'WindowsExports' => 'os/windows_exports',
    'GNUExports' => 'os/gnu_exports',
    'Debugger' => 'debug',
    'LinOS' => 'os/linux', 'WinOS' => 'os/windows',
    'GdbClient' => 'os/remote',
    'Disassembler' => 'disassemble',
    'Decompiler' => 'decompile',
    'DynLdr' => 'dynldr',
  }

  # use the Module.autoload ruby functionnality to load framework components on demand
  Const_autorequire.each { |cst, file|
    autoload cst, File.join('metasm', file)
  }

  Const_autorequire_equiv.each { |cst, eqv|
    file = Const_autorequire[eqv]
    autoload cst, File.join('metasm', file)
  }
end

# load Metasm core files
%w[main encode decode render exe_format/main os/main].each { |f|
  require File.join('metasm', f)
}


# remove an 1.9 warning, couldn't find a compatible way...
if Hash.new.respond_to?(:key)
  puts "using ruby1.9 workaround for Hash#index warning" if $DEBUG
  class Hash
    alias index_premetasm index rescue nil
    undef index rescue nil
    alias index key
  end
end
