#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/exe_format/main'

module Metasm
# special class that decodes a PE, ELF, MachO or UnivBinary file from its signature
# XXX UnivBinary is not a real ExeFormat, just a container..
class AutoExe < ExeFormat
class UnknownSignature < InvalidExeFormat ; end

# actually calls autoexe_load for the detected filetype from #execlass_from_signature
def self.load(str, *a, &b)
  s = str
  s = str.data if s.kind_of? EncodedData
  execlass_from_signature(s).autoexe_load(str, *a, &b)
end

# match the actual exe class from the raw file inspection using the registered signature list
# calls #unknown_signature if nothing matches
def self.execlass_from_signature(raw)
  m = @signatures.find { |sig, exe|
    case sig
    when String; raw[0, sig.length] == sig
    when Proc; sig[raw]
    end
  }
  e = m ? m[1] : unknown_signature(raw)
  case e
  when String; Metasm.const_get(e)
  when Proc; e.call
  else e
  end
end

# register a new binary file signature
def self.register_signature(sig, exe=nil, &b)
  (@signatures ||= []) << [sig, exe || b]
end

def self.init_signatures(sig=[])
  @signatures = sig
end

# this function is called when no signature matches
def self.unknown_signature(raw)
  raise UnknownSignature, "unrecognized executable file format #{raw[0, 4].unpack('H*').first.inspect}"
end

# raw signature copies (avoid triggering exefmt autorequire)
init_signatures
register_signature("\x7fELF") { ELF }
register_signature(lambda { |raw| raw[0, 2] == "MZ" and off = raw[0x3c, 4].to_s.unpack('V')[0] and off < raw.length and raw[off, 4] == "PE\0\0" }) { PE }
%w[feedface cefaedfe feedfacf cffaedfe].each { |sig| register_signature([sig].pack('H*')) { MachO } }
register_signature("\xca\xfe\xba\xbe") { UniversalBinary }
register_signature("dex\n") { DEX }
register_signature("dey\n") { DEY }
register_signature("\xfa\x70\x0e\x1f") { FatELF }
register_signature('Metasm.dasm') { Disassembler }

# replacement for AutoExe where #load defaults to a Shellcode of the specified CPU
def self.orshellcode(cpu=nil, &b)
  # here we create an anonymous subclass of AutoExe whose #unknown_sig is patched to return a Shellcode instead of raise()ing
  c = ::Class.new(self)
  # yeeehaa
  class << c ; self ; end.send(:define_method, :unknown_signature) { |raw|
    Shellcode.withcpu(cpu || b[raw])
  }
  c.init_signatures @signatures
  c
end
end

# special class that decodes a LoadedPE or LoadedELF from its signature (used to read memory-mapped binaries)
class LoadedAutoExe < AutoExe
init_signatures
register_signature("\x7fELF") { LoadedELF }
register_signature(lambda { |raw| raw[0, 2] == "MZ" and off = raw[0x3c, 4].to_s.unpack('V')[0] and off < raw.length and raw[off, 4] == "PE\0\0" }) { LoadedPE }
end
end
