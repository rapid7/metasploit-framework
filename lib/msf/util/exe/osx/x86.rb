module Msf::Util::EXE::OSX::x86
  include Msf::Util::EXE::OSX::Common

  def to_executable(framework, code, opts = {}, fmt='macho')
    return to_osx_x86_macho(framework, code, opts) if fmt == 'macho'
  end

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
    Payload::MachO.new(mo).sign
    mo
  end
end