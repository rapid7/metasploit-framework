module Msf::Util::EXE::OSX::X64
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::OSX::Common

  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods    
    # Create an x86_64 OSX Mach-O containing the payload provided in +code+  
    # self.to_osx_x64_macho
    #
    # @param framework  [Msf::Framework]  The framework of you want to use
    # @param code       [String]
    # @param opts       [Hash]
    # @option           [String] :template
    # @return           [String]
    def to_osx_x64_macho(framework, code, opts = {})
      set_template_default(opts, "template_x64_darwin.bin")

      macho = self.get_file_contents(opts[:template])
      bin = self.find_payload_tag(macho,
              "Invalid Mac OS X x86_64 Mach-O template: missing \"PAYLOAD:\" tag")
      macho[bin, code.length] = code
      macho
    end
  end
  class << self
    include ClassMethods
  end
end
