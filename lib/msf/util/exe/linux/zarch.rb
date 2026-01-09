module Msf::Util::EXE::Linux::Zarch
  include Msf::Util::EXE::Linux::Common
  
  def to_executable(framework, code, opts = {}, fmt='elf')
    return to_linux_zarch_elf(framework, code, opts) if fmt == 'elf'
    return to_linux_zarch_elf_dll(framework, code, opts) if fmt == 'elf-so'
  end  
  # Create a ZARCH Linux ELF containing the payload provided in +code+
  #
  # @param framework [Msf::Framework]
  # @param code       [String]
  # @param opts       [Hash]
  # @option           [String] :template
  # @return           [String] Returns an elf
  def to_linux_zarch_elf(framework, code, opts = {})
    to_exe_elf(framework, opts, "template_zarch_linux.bin", code)
  end

  # Create a ZARCH Linux ELF_DYN containing the payload provided in +code+
  #
  # @param framework [Msf::Framework]
  # @param code       [String]
  # @param opts       [Hash]
  # @option           [String] :template
  # @return           [String] Returns an elf
  def to_linux_zarch_elf_dll(framework, code, opts = {})
    to_exe_elf(framework, opts, "template_zarch_linux_dll.bin", code)
  end
end