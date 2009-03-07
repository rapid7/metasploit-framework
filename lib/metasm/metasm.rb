#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


Metasmdir = File.dirname(__FILE__)

module Metasm
def self.const_missing(c, fallback=nil)
	#puts "const_missing #{c.inspect}"
	# constant defined in the same file as another
	cst = {
		'X86' => 'Ia32', 'PPC' => 'PowerPC',
		'UniversalBinary' => 'MachO', 'COFFArchive' => 'COFF',
		'PTrace32' => 'LinOS', 'GNUExports' => 'LinOS',
		'LoadedELF' => 'ELF', 'LoadedPE' => 'PE',
		'LinuxRemoteString' => 'LinOS',
		'WinAPI' => 'WinOS', 'WindowsExports' => 'WinOS',
		'WindowsRemoteString' => 'WinOS', 'WinDbg' => 'WinOS',
		'VirtualFile' => 'OS', 'VirtualString' => 'OS',
		'EncodedData' => 'Expression', 'ExpressionType' => 'Expression',
	}[c.to_s] || c.to_s

	files = {
		'Ia32' => 'ia32', 'MIPS' => 'mips', 'PowerPC' => 'ppc',
		'C' => ['parse_c', 'compile_c'],
		'MZ' => 'exe_format/mz', 'PE' => 'exe_format/pe',
		'ELF' => ['exe_format/elf_encode', 'exe_format/elf_decode'],
		'COFF' => ['exe_format/coff_encode', 'exe_format/coff_decode'],
		'Shellcode' => 'exe_format/shellcode', 'AutoExe' => 'exe_format/autoexe',
		'AOut' => 'exe_format/a_out', 'MachO' => 'exe_format/macho',
		'NDS' => 'exe_format/nds', 'XCoff' => 'exe_format/xcoff',
		'GtkGui' => 'gui/gtk',
		'OS' => 'os/main',
		'LinOS' => 'os/linux', 'WinOS' => 'os/windows',
		'Preprocessor' => 'preprocessor',
		'Disassembler' => 'decode', 'Expression' => ['main', 'encode', 'decode'],
		'Decompiler' => 'decompile',
	}[cst]

	return(fallback ? fallback[c] : super(c)) if not files

	files = [files] if files.kind_of? ::String
	#puts "autorequire #{files.join(', ')}"

	# temporarily put the current file directory in the ruby include path
	if not $:.include? Metasmdir
		incdir = Metasmdir
		$: << incdir
	end
	files.each { |f| require File.join('metasm', f) }
	$:.delete incdir if incdir

	const_get c
end
end

# needed for subclasses (e.g. Metasm::PE, to avoid Metasm::PE::Ia32: const not found)
class << Object
alias premetasm_const_missing const_missing
def const_missing(c)
	# RHAAAAAAAAAAA
	# we want Metasm.const_missing to be used only for classes in the Metasm module
	# so either a subclass (eg Metasm::PE => #name starts with 'Metasm::')
	# or the Metasm module itself, when it is included elsewhere (ancestors check)
	if name =~ /^Metasm::/ or ancestors.include? Metasm
		Metasm.const_missing(c, method(:premetasm_const_missing))
	else
		premetasm_const_missing(c)
	end
end
end
