module Msf::Util::EXE::Linux::Ppc
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::Linux::Common

  def self.included(base)
    base.extend(ClassMethods)
  end
  
  module ClassMethods

    # Create a PPC 32-bit BE Linux ELF containing the payload provided in +code+
    # to_linux_ppc_elf
    #
    # @param framework [Msf::Framework]
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String] Returns an elf
    def to_linux_ppc_elf(framework, code, opts = {})
      to_exe_elf(framework, opts, "template_ppc_linux.bin", code)
    end
  end

  class << self
    include ClassMethods
  end


end
