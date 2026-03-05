module Msf::Util::EXE::OSX
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::OSX::Common
  include Msf::Util::EXE::OSX::X86
  include Msf::Util::EXE::OSX::X64
  include Msf::Util::EXE::OSX::Armle
  include Msf::Util::EXE::OSX::Aarch64

  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    def to_executable_osx(framework, arch, code, fmt = 'macho', opts = {})
      exe_formats = ['macho', 'app']
      exe_fmt = 'macho'
      exe_fmt = fmt if exe_formats.include?(fmt)

      exe = nil
      exe = to_executable_osx_x86(framework, code, exe_fmt, opts) if arch.index(ARCH_X86)
      exe = to_executable_osx_x64(framework, code, exe_fmt, opts) if arch.index(ARCH_X64)
      exe = to_executable_osx_armle(framework, code, exe_fmt, opts) if arch.index(ARCH_ARMLE)
      exe = to_executable_osx_aarch64(framework, code, exe_fmt, opts) if arch.index(ARCH_AARCH64)
      exe = to_executable_osx_app(framework, code, exe_fmt, opts) if fmt == 'app'
      exe = to_executable_osx_ppc(framework, code, exe_fmt, opts) if arch.index(ARCH_PPC)
      
      return exe if exe_formats.include?(fmt) # Returning only the exe
    end

    def to_executable_osx_x86(framework, code, fmt = 'macho', opts = {})
      return to_osx_x86_macho(framework, code, opts) if fmt == 'macho'
    end

    def to_executable_osx_x64(framework, code, fmt = 'macho', opts = {})
      return to_osx_x64_macho(framework, code, opts) if fmt == 'macho'
    end

    def to_executable_osx_armle(framework, code, fmt = 'macho', opts = {})
      return to_osx_armle_macho(framework, code, opts) if fmt == 'macho'
    end

    def to_executable_osx_aarch64(framework, code, fmt = 'macho', opts = {})
      return to_osx_aarch64_macho(framework, code, opts) if fmt == 'macho'
    end

    def to_executable_osx_app(framework, code, fmt = 'app', opts = {})
      return to_osx_app(code, opts) if fmt == 'app'
    end

    def to_executable_osx_ppc(framework, code, fmt = 'macho', opts = {})
      return to_osx_ppc_macho(framework, code, opts) if fmt == 'macho'
    end
  end
  class << self
    include ClassMethods
  end
end
