module Msf::Util::EXE::Bsd
  def to_executable(framework, arch, code, opts = {}, fmt = 'elf')
    return EXE::Bsd::X86.to_executable(framework, code, opts, fmt) if arch =~ /x86|i386/i
    return EXE::Bsd::X64.to_executable(framework, code, opts, fmt) if arch =~ /x64|amd64/i
    nil
  end
end