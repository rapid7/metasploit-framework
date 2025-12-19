module Msf::Util::EXE::Linux::Mipsbe
  include Msf::Util::EXE::Linux::Common

  def to_executable(framework, code, opts = {}, fmt='elf')
    return to_linux_mipsbe_elf(framework, code, opts) if fmt == 'elf'
    # return to_linux_mipsbe_elf_dll(framework, code, opts) if fmt == 'elf-so' Not yet implemented
  end

  # Create a MIPSBE 64-bit BE Linux ELF containing the payload provided in +code+
  # to_linux_mipsbe_elf
  #
  # @param framework [Msf::Framework]
  # @param code       [String]
  # @param opts       [Hash]
  # @option           [String] :template
  # @return           [String] Returns an elf
  def to_linux_mipsbe_elf(framework, code, opts = {})
    to_exe_elf(framework, opts, "template_mipsbe_linux.bin", code, true)
  end
end