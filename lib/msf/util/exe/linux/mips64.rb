module Msf::Util::EXE::Linux::Mips64
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::Linux::Common
  def self.included(base)
    base.extend(ClassMethods)
  end
  
  module ClassMethods

    # Create a MIPS64 64-bit LE Linux ELF containing the payload provided in +code+
    # to_linux_mips64_elf
    #
    # @param framework [Msf::Framework]
    # @param code       [String]            
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String] Returns an elf
    def to_linux_mips64_elf(framework, code, opts = {})
      Msf::Util::EXE::Common.to_exe_elf(framework, opts, "template_mips64_linux.bin", code)
    end
  end

  class << self
    include ClassMethods
  end

end
