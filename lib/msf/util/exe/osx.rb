module Msf::Util::EXE::OSX
  def to_executable(framework, arch, code, opts = {}, fmt = 'macho')
    osx = Object.new.extend(Msf::Util::EXE::Common)
    osx.extend(Msf::Util::EXE::OSX::Common)
    osx.extend(Msf::Util::EXE::OSX::X86) if arch =~ /x86|i386/i
    osx.extend(Msf::Util::EXE::OSX::X64) if arch =~ /x64|amd64/i
    osx.extend(Msf::Util::EXE::OSX::Armle) if arch =~ /armle|armv7/i
    osx.extend(Msf::Util::EXE::OSX::Aarch64) if arch =~ /aarch64|arm64/i
    return osx.to_executable(framework, code, opts, fmt) if osx.respond_to?(:to_executable)

    nil
  end

