module Msf::Util::EXE::Linux
  def to_executable(framework, arch, code, opts = {}, fmt = 'elf')
    linux = Object.new.extend(Msf::Util::EXE::Common)
    linux.extend(Msf::Util::EXE::Linux::Common)
    linux.extend(Msf::Util::EXE::Linux::Common)
    linux.extend(Msf::Util::EXE::Linux::X86) if arch =~ /x86|i386/i
    linux.extend(Msf::Util::EXE::Linux::X64) if arch =~ /x64|x86_64|amd64/i
    linux.extend(Msf::Util::EXE::Linux::Aarch64) if arch =~ /aarch64|arm64/i
    linux.extend(Msf::Util::EXE::Linux::Armle) if arch =~ /armle|armv7l/i
    return linux.to_executable(framework, code, opts, fmt) if linux.respond_to?(:to_executable)
    nil
  end
end