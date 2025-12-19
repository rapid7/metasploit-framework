 module Msf::Util::EXE::OSX::Ppc
  include Msf::Util::EXE::OSX::Common

  def to_executable(framework, code, opts = {}, fmt='macho')
    return to_osx_ppc_macho(framework, code, opts) if fmt == 'macho'
  end
  
  # Create a PPC OSX Mach-O containing the payload provided in +code+ 
  # to_osx_ppc_macho
  #
  # @param framework  [Msf::Framework]  The framework of you want to use
  # @param code       [String]
  # @param opts       [Hash]
  # @option           [String] :template
  # @return           [String]
  def to_osx_ppc_macho(framework, code, opts = {})

    # Allow the user to specify their own template
    set_template_default(opts, "template_ppc_darwin.bin")

    mo = self.get_file_contents(opts[:template])
    bo = self.find_payload_tag(mo, "Invalid OSX PPC Mach-O template: missing \"PAYLOAD:\" tag")
    mo[bo, code.length] = code
    mo
  end
end
