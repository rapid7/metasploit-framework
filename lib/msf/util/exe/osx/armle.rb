module Msf::Util::EXE::OSX::Armle
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::OSX::Common
  
  def self.included(base)
    base.extend(ClassMethods)
  end
  
  module ClassMethods
    # Create an ARM Little Endian OSX Mach-O containing the payload provided in +code+
    # self.to_osx_arm_macho
    #
    # @param framework  [Msf::Framework]  The framework of you want to use
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String]
    def to_osx_arm_macho(framework, code, opts = {})
      to_executable_with_template("template_armle_darwin.bin", framework, code, opts)
    end
  end
  class << self
    include ClassMethods
  end
end
