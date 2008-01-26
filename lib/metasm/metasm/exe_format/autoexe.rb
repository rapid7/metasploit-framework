#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/exe_format/main'

module Metasm
# special class that decodes a PE or ELF file from its signature
# does not support other exeformats (for now)
class AutoExe < ExeFormat
def self.load(str, *a)
	s = str
	s = str.data if s.kind_of? EncodedData
	if s[0, 4] == "\x7fELF": ELF
	elsif off = s[0x3c, 4].unpack('V').first and s[off, 4] == "PE\0\0": PE
	else raise 'unrecognized executable file format'
	end.load(str, *a)
end
end
end
