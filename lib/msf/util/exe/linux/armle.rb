module Msf::Util::EXE::Linux::Armle
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::Linux::Common
  
  def self.included(base)
    base.extend(ClassMethods)
  end
  
  module ClassMethods

    # Create a ARM Little Endian Linux ELF containing the payload provided in +code+
    # to_linux_armle_elf
    #
    # @param framework [Msf::Framework]
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String] Returns an elf
    def to_linux_armle_elf(framework, code, opts = {})
      to_exe_elf(framework, opts, "template_armle_linux.bin", code)
    end

    # Create a ARM Little Endian Linux ELF_DYN containing the payload provided in +code+
    # to_linux_armle_elf_dll
    #
    # @param framework [Msf::Framework]
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String] Returns an elf-so
    def to_linux_armle_elf_dll(framework, code, opts = {})
      to_exe_elf(framework, opts, "template_armle_linux_dll.bin", code)
    end
  end

  class << self
    include ClassMethods
  end

end
