module Msf::Util::EXE::Linux::Aarch64
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::Linux::Common

  def self.included(base)
    base.extend(ClassMethods)
  end
  
  module ClassMethods
  
    # Create a AARCH64 64-bit LE Linux ELF containing the payload provided in +code+  
    # to_linux_aarch64_elf
    #
    # @param framework [Msf::Framework]
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String] Returns an elf
    def to_linux_aarch64_elf(framework, code, opts = {})
      to_exe_elf(framework, opts, "template_aarch64_linux.bin", code)
    end

    # Create a AARCH64 Linux ELF_DYN containing the payload provided in +code+
    #
    # @param framework [Msf::Framework]
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String] Returns an elf
    def to_linux_aarch64_elf_dll(framework, code, opts = {})
      to_exe_elf(framework, opts, "template_aarch64_linux_dll.bin", code)
    end
  end

  class << self
    include ClassMethods
  end

end
