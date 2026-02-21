module Msf::Util::EXE::Bsd::X64
  include Msf::Util::EXE::Common

  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    # Create a 64-bit Linux ELF containing the payload provided in +code+
    #
    # @param framework [Msf::Framework]
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String] Returns an elf
    def to_bsd_x64_elf(framework, code, opts = {})
      to_exe_elf(framework, opts, "template_x64_bsd.bin", code)
    end
  end

  class << self
    include ClassMethods
  end
end
