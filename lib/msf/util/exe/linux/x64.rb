module Msf::Util::EXE::Linux::X64
include Msf::Util::EXE::Linux::Common
  
  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods

    # Create a 64-bit Linux ELF containing the payload provided in +code+
    # to_linux_x64_elf
    #
    # @param framework [Msf::Framework]
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String] Returns an elf
    def to_linux_x64_elf(framework, code, opts = {})
      Msf::Util::EXE::Common.to_exe_elf(framework, opts, "template_x64_linux.bin", code)
    end
    
    # Create a 64-bit Linux ELF_DYN containing the payload provided in +code+
    # to_linux_x64_elf_dll
    #
    # @param framework [Msf::Framework]
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String] Returns an elf
    def to_linux_x64_elf_dll(framework, code, opts = {})
      Msf::Util::EXE::Common.to_exe_elf(framework, opts, "template_x64_linux_dll.bin", code)
    end

      # Create a 64-bit Linux ELF containing the payload provided in +code+
      # to_linux_x64_elf
      #
      # @param framework [Msf::Framework]
      # @param code       [String]
      # @param opts       [Hash]
      # @option           [String] :template
      # @return           [String] Returns an elf
      def to_linux_x64_elf(framework, code, opts = {})
        to_exe_elf(framework, opts, "template_x64_linux.bin", code)
      end
  end

  class << self
    include ClassMethods
  end
end
