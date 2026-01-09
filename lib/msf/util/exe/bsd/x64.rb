module Msf::Util::EXE::BSD::X64
  include Msf::Util::EXE::Common

  def to_executable(framework, code, opts = {}, fmt='elf')
    return to_bsd_x64_elf(framework, code, opts) if fmt == 'elf'
    #return to_bsd_x64_elf_dll(framework, code, opts) if fmt == 'elf-so' Not yet implemented
  end

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
