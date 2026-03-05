module Msf::Util::EXE::Linux
  
  include Msf::Util::EXE::Linux::Common
  include Msf::Util::EXE::Linux::Aarch64
  include Msf::Util::EXE::Linux::Armle
  include Msf::Util::EXE::Linux::Armbe
  include Msf::Util::EXE::Linux::Loongarch64
  include Msf::Util::EXE::Linux::Mips64
  include Msf::Util::EXE::Linux::Mipsbe
  include Msf::Util::EXE::Linux::Mipsle
  include Msf::Util::EXE::Linux::Ppc
  include Msf::Util::EXE::Linux::Ppc64
  include Msf::Util::EXE::Linux::Ppce500v2 
  include Msf::Util::EXE::Linux::Riscv32le
  include Msf::Util::EXE::Linux::Riscv32le
  include Msf::Util::EXE::Linux::X64
  include Msf::Util::EXE::Linux::X86
  include Msf::Util::EXE::Linux::Zarch

  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    def to_executable_linux(framework, arch, code, fmt = 'elf', opts = {})
      
      elf_formats = ['elf','elf-so']
      elf_fmt = 'elf'
      elf_fmt = fmt if elf_formats.include?(fmt)

      elf = to_executable_linux_x86(framework, code, elf_fmt, opts) if arch.index(ARCH_X86)
      elf = to_executable_linux_x64(framework, code, elf_fmt,opts) if arch.index(ARCH_X64)
      elf = to_executable_linux_armle(framework, code, elf_fmt,opts) if arch.index(ARCH_ARMLE)
      elf = to_executable_linux_armbe(framework, code, elf_fmt,opts) if arch.index(ARCH_ARMBE)
      elf = to_executable_linux_aarch64(framework, code, elf_fmt,opts) if arch.index(ARCH_AARCH64)
      elf = to_executable_linux_mipsbe(framework, code, elf_fmt,opts) if arch.index(ARCH_MIPSBE)
      elf = to_executable_linux_mipsle(framework, code, elf_fmt,opts) if arch.index(ARCH_MIPSLE)
      elf = to_executable_linux_mips64(framework, code, elf_fmt,opts) if arch.index(ARCH_MIPS64)
      elf = to_executable_linux_ppc(framework, code, elf_fmt,opts) if arch.index(ARCH_PPC)
      elf = to_executable_linux_ppc64(framework, code, elf_fmt,opts) if arch.index(ARCH_PPC64LE)
      elf = to_executable_linux_ppce500v2(framework, code, elf_fmt,opts) if arch.index(ARCH_PPCE500V2)
      elf = to_executable_linux_riscv32le(framework, code,elf_fmt, opts) if arch.index(ARCH_RISCV32LE)
      elf = to_executable_linux_riscv64le(framework, code, elf_fmt,opts) if arch.index(ARCH_RISCV64LE)
      elf = to_executable_linux_zarch(framework, code, elf_fmt,opts) if arch.index(ARCH_ZARCH)
      elf = to_executable_linux_loongarch64(framework, code, elf_fmt,opts) if arch.index(ARCH_LOONGARCH64)

      return elf if elf_formats.include?(fmt) # Returning only the elf
    end
    
    def to_executable_linux_x64(framework, code, fmt = 'elf', opts = {})
      return to_linux_x64_elf(framework, code, opts) if fmt == 'elf'
      return to_linux_x64_elf_dll(framework, code, opts) if fmt == 'elf-so'
    end
    
    def to_executable_linux_x86(framework, code, fmt = 'exe', opts = {})
      return to_linux_x86_elf(framework, code, opts) if fmt == 'elf'
      return to_linux_x86_elf_dll(framework, code, opts) if fmt == 'elf-so'
    end

    def to_executable_linux_armle(framework, code, fmt = 'elf', opts = {})
      return to_linux_armle_elf(framework, code, opts) if fmt == 'elf'
      return to_linux_armle_elf_dll(framework, code, opts) if fmt == 'elf-so'
    end

    def to_executable_linux_armbe(framework, code, fmt = 'elf', opts = {})
      return to_linux_armbe_elf(framework, code, opts) if fmt == 'elf'
    end

    def to_executable_linux_aarch64(framework, code, fmt = 'elf', opts = {})
      return to_linux_aarch64_elf(framework, code, opts) if fmt == 'elf'
      return to_linux_aarch64_elf_dll(framework, code, opts) if fmt == 'elf-so'
    end

    def to_executable_linux_mipsbe(framework, code, fmt = 'elf', opts = {})
      return to_linux_mipsbe_elf(framework, code, opts) if fmt == 'elf'
    end

    def to_executable_linux_mipsle(framework, code, fmt = 'elf', opts = {})
      return to_linux_mipsle_elf(framework, code, opts) if fmt == 'elf'
    end

    def to_executable_linux_mips64(framework, code, fmt = 'elf', opts = {})
      return to_linux_mips64_elf(framework, code, opts) if fmt == 'elf'
    end

    def to_executable_linux_ppc(framework, code, fmt = 'elf', opts = {})
      return to_linux_ppc_elf(framework, code, opts) if fmt == 'elf'
    end
    
    def to_executable_linux_ppc64(framework, code, fmt = 'elf', opts = {})
      return to_linux_ppc64_elf(framework, code, opts) if fmt == 'elf'
    end

    def to_executable_linux_ppce500v2(framework, code, fmt = 'elf', opts = {})
      return to_linux_ppce500v2_elf(framework, code, opts) if fmt == 'elf'
    end

    def to_executable_linux_riscv32le(framework, code, fmt = 'elf', opts = {})
      return to_linux_riscv32le_elf(framework, code, opts) if fmt == 'elf'
      return to_linux_riscv32le_elf_dll(framework, code, opts) if fmt == 'elf-so'
    end

    def to_executable_linux_riscv64le(framework, code, fmt = 'elf', opts = {})
      return to_linux_riscv64le_elf(framework, code, opts) if fmt == 'elf'
      return to_linux_riscv64le_elf_dll(framework, code, opts) if fmt == 'elf-so'
    end

    def to_executable_linux_zarch(framework, code, fmt = 'elf', opts = {})
      return to_linux_zarch_elf(framework, code, opts) if fmt == 'elf'
    end

    def to_executable_linux_loongarch64(framework, code, fmt = 'elf', opts = {})
      return to_linux_loongarch64_elf(framework, code, opts) if fmt == 'elf'
      return to_linux_loongarch64_elf_dll(framework, code, opts) if fmt == 'elf-so'
    end
  end

  class << self
    include ClassMethods
  end
end
