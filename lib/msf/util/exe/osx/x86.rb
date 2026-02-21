module Msf::Util::EXE::OSX::X86
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::OSX::Common
  
  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    # Create an x86 OSX Mach-O containing the payload provided in +code+
    # to_osx_x86_macho
    #
    # @param framework  [Msf::Framework]  The framework of you want to use
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String]
    def to_osx_x86_macho(framework, code, opts = {})
      mo = to_executable_with_template("template_x86_darwin.bin", framework, code, opts)
      Msf::Payload::MachO.new(mo).sign
      mo
    end
  end
  
  class << self
    include ClassMethods
  end

end
