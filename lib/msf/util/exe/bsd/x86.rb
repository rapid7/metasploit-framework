module Msf::Util::EXE::BSD::X86
  include Msf::Util::EXE::Common

  def to_executable(framework, code, opts = {}, fmt='elf')
    return to_bsd_x86_elf(framework, code, opts) if fmt == 'elf'
    # return to_bsd_x86_elf_dll(framework, code, opts) if fmt == 'elf-so' Not yet implemented
  end

  # Create a 32-bit BSD (test on FreeBSD) ELF containing the payload provided in +code+
  #
  # @param framework [Msf::Framework]
  # @param code       [String]
  # @param opts       [Hash]
  # @option           [String] :template
  # @return           [String] Returns an elf
  def self.to_bsd_x86_elf(framework, code, opts = {})
    to_exe_elf(framework, opts, "template_x86_bsd.bin", code)
  end
end