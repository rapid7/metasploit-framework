module Msf::Util::EXE::Bsd
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::Bsd::X86
  include Msf::Util::EXE::Bsd::X64

  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    def to_executable_bsd(framework, arch, code, fmt = 'elf', opts = {})
      exe_formats = ['elf', 'elf-so']
      exe_fmt = 'elf'
      exe_fmt = fmt if exe_formats.include?(fmt)

      exe = nil
      exe = to_executable_bsd_x86(framework, code, exe_fmt, opts) if arch.index(ARCH_X86)
      exe = to_executable_bsd_x64(framework, code, exe_fmt, opts) if arch.index(ARCH_X64)
      #exe = to_executable_bsd_armle(framework, code, exe_fmt, opts) if arch =~ /armle|armv7l/i Not yet implemented
      #exe = to_executable_bsd_aarch64(framework, code, exe_fmt, opts) if arch =~ /aarch64|arm64/i Not yet implemented

      return exe if exe_formats.include?(fmt) # Returning only the exe
      nil
    end

    def to_executable_bsd_x86(framework, code, fmt = 'elf', opts = {})
      return to_bsd_x86_elf(framework, code, opts) if fmt == 'elf'
      # return to_bsd_x86_elf_dll(framework, code, opts) if fmt == 'elf-so' Not yet implemented
    end

    def to_executable_bsd_x64(framework, code, fmt = 'elf', opts = {})
      return to_bsd_x64_elf(framework, code, opts) if fmt == 'elf'
      #return to_bsd_x64_elf_dll(framework, code, opts) if fmt == 'elf-so' Not yet implemented
    end
  end

  class << self
    include ClassMethods
  end
end
