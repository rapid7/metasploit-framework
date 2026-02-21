module Msf::Util::EXE::Linux::Riscv64le
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::Linux::Common

  def self.included(base)
    base.extend(ClassMethods)
  end
  
  module ClassMethods

    # Create a RISC-V 64-bit LE Linux ELF containing the payload provided in +code+
    # to_linux_riscv64le_elf
    #
    # @param framework [Msf::Framework]
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String] Returns an elf
    def to_linux_riscv64le_elf(framework, code, opts = {})
      to_exe_elf(framework, opts, "template_riscv64le_linux.bin", code)
    end

    # Create a RISC-V 64-bit LE Linux ELF_DYN containing the payload provided in +code+
    # to_linux_riscv64le_elf_dll
    #
    # @param framework [Msf::Framework]
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String] Returns an elf
    def to_linux_riscv64le_elf_dll(framework, code, opts = {})
      to_exe_elf(framework, opts, "template_riscv64le_linux_dll.bin", code)
    end
  end

  class << self
    include ClassMethods
  end

end
