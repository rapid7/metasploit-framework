#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/exe_format/main'

module Metasm
# special class that decodes a PE, ELF, MachO or UnivBinary file from its signature
# XXX UnivBinary is not a real ExeFormat, just a container..
class AutoExe < ExeFormat
class UnknownSignature < InvalidExeFormat ; end
def self.load(str, *a)
	s = str
	s = str.data if s.kind_of? EncodedData
	execlass_from_signature(s).autoexe_load(str, *a)
end
def self.execlass_from_signature(raw)
	if raw[0, 4] == ELF::MAGIC; ELF
	elsif raw[0, 2] == MZ::MAGIC and off = raw[0x3c, 4].to_s.unpack('V').first and off < raw.length and raw[off, 4] == PE::MAGIC; PE
	elsif raw[0, 4] == UniversalBinary::MAGIC; UniversalBinary
	elsif MachO::MAGICS.include? raw[0, 4]; MachO
	else raise UnknownSignature, "unrecognized executable file format #{raw[0, 4].unpack('H*').first.inspect}"
	end
end
def self.orshellcode(cpu)
	# here we create an anonymous subclass of AutoExe whose #exe_from_sig is patched to return a Shellcode if no signature is recognized (instead of raise()ing)
	c = ::Class.new(self)
	# yeeehaa
	class << c ; self ; end.send(:define_method, :execlass_from_signature) { |raw|
		begin
			super(raw)
		rescue UnknownSignature
			Shellcode.withcpu(cpu)
		end
	}
	c
end
end
end
