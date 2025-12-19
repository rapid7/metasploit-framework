module Msf::Util::EXE::Solaris::X86
  include Msf::Util::EXE::Common

  def to_executable(framework, code, opts = {}, fmt='elf')
    return self.to_solaris_x86_elf(framework, code, opts) if fmt == 'elf'
  end 
  # Create a 32-bit Solaris ELF containing the payload provided in +code+
  #
  # @param framework [Msf::Framework]
  # @param code       [String]
  # @param opts       [Hash]
  # @option           [String] :template
  # @return           [String] Returns an elf
  def self.to_solaris_x86_elf(framework, code, opts = {})
    to_exe_elf(framework, opts, "template_x86_solaris.bin", code)
  end
end