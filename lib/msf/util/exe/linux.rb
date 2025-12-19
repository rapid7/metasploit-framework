module Msf::Util::EXE::Linux
  def to_executable(framework, arch, code, opts = {}, fmt = 'elf')
    return EXE::Linux::X86.to_executable(framework, code, opts, fmt) if arch =~ /x86|i386/i
    return EXE::Linux::X64.to_executable(framework, code, opts, fmt) if arch =~ /x64|amd64/i
    return EXE::Linux::Aarch64.to_executable(framework, code, opts, fmt) if arch =~ /aarch64|arm64/i
    return EXE::Linux::Armle.to_executable(framework, code, opts, fmt) if arch =~ /armle|armv7l/i
    nil
  end
end