module Msf::Util::EXE::OSX
  def to_executable(framework, arch, code, opts = {}, fmt = 'macho')
    return Msf::Util::EXE::OSX::Armle::to_executable(framework, code, opts, fmt) if arch =~ /armle|armv7/i
    return Msf::Util::EXE::OSX::Aarch64::to_executable(framework, code, opts, fmt) if arch =~ /aarch64|arm64/i
    return Msf::Util::EXE::OSX::X86::to_executable(framework, code, opts, fmt) if arch =~ /x86|i386/i
    return Msf::Util::EXE::OSX::X64::to_executable(framework, code, opts, fmt) if arch =~ /x64|amd64/i
    nil
  end

