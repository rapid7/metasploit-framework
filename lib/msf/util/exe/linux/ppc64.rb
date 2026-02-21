module Msf::Util::EXE::Linux::Ppc64
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::Linux::Common
  def self.included(base)
    base.extend(ClassMethods)
  end
  
  module ClassMethods

    # Create a PPC64 64-bit BE Linux ELF containing the payload provided in +code+
    # to_linux_ppc64_elf
    #
    # @param framework [Msf::Framework]
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String] Returns an elf
    def to_linux_ppc64_elf(framework, code, opts = {})
      to_exe_elf(framework, opts, "template_ppc64_linux.bin", code, true)
    end
  end

  class << self
    include ClassMethods
  end


end
