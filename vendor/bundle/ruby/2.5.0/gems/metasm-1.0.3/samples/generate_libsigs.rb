#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# this generates a signature file for all function in the given library
# usage: gensigs.rb some_lib.a somefile.o somelib.lib > mylib.fsigs
#
# to be used with the match_libsigs disassembler plugin

# TODO handle COFF symbols (for .lib)

require 'metasm'

include Metasm

AutoExe.register_signature("!<arch>\n", COFFArchive)
AutoExe.register_signature("\x4c\x01", COFF)	# no signature, check the machine field = i386

# minimum number of raw bytes to allow in a signature
$min_sigbytes = 8

# read a binary file, print a signature for all symbols found
def create_sig(exe)
	func = case exe
	when COFFArchive; :create_sig_arch
	when PE, COFF; :create_sig_coff
	when ELF; :create_sig_elf
	else raise 'unsupported file format'
	end
	send(func, exe) { |sym, edata|
		sig = edata.data.unpack('H*').first
		edata.reloc.each { |o, r|
# TODO if the reloc points to a known func (eg WinMain), keep the info
			sz = r.length
			sig[2*o, 2*sz] = '.' * sz * 2
		}

		next if sig.gsub('.', '').length < 2*$min_sigbytes

		puts sym
		sig.scan(/.{1,78}/) { |s| puts ' ' + s }
	}
end

# handle coff archives
def create_sig_arch(exe)
	exe.members.each { |m|
		next if m.name == '/' or m.name == '//'
		obj = m.exe rescue next
		create_sig(obj)
	}
end

# scan an elf file
def create_sig_elf(elf)
	elf.symbols.each { |sym|
		next if sym.type != 'FUNC' or sym.shndx == 'UNDEF'
		if elf.header.type == 'REL'
			next if not data = elf.sections[sym.shndx].encoded
			off = sym.value
		else
			next if not seg = elf.segments.find { |s| s.type == 'LOAD' and sym.value >= s.vaddr and sym.value < s.vaddr+s.memsz }
			next if not data = seg.encoded
			off = sym.value - seg.vaddr
		end

		len = sym.size
		if len == 0
			len = data.export.find_all { |k, o| o > off and k !~ /_uuid/ }.transpose[1].to_a.min || data.length
			len -= off
			len = 256 if len > 256
		end

		yield sym.name, data[off, len]
	}
end

# scan a pe/coff file
def create_sig_coff(coff)
	if coff.kind_of? PE	# dll
		# dll
		# TODO
	else
		coff.symbols.to_a.compact.each { |sym|
			next if sym.type != 'FUNCTION'
			next if not sym.sec_nr.kind_of? Integer
			data = coff.sections[sym.sec_nr-1].encoded
			off = sym.value
			len = data.export.find_all { |k, o| o > off and k !~ /_uuid/ }.transpose[1].to_a.min || data.length

			yield sym.name, data[off, len]
		}
	end
end

if __FILE__ == $0
	$min_sigbytes = ARGV.shift.to_i if ARGV.first =~ /^\d+$/
	targets = ARGV
	targets = Dir['*.a'] + Dir['*.lib'] if targets.empty?
	targets.each { |t| create_sig(AutoExe.decode_file(t)) }
end
