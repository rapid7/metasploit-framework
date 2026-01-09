module Msf::Util::EXE::Windows
  def to_executable(framework, arch, code, opts = {}, fmt='exe')
    windows = Object.new.extend(Msf::Util::EXE::Common)
    windows.extend(Msf::Util::EXE::Windows::Common)
    windows.extend(Msf::Util::EXE::Windows::X86) if arch =~ /x86|i386/i
    windows.extend(Msf::Util::EXE::Windows::X64) if arch =~ /x64|amd64/i
    windows.extend(Msf::Util::EXE::Windows::Aarch64) if arch =~ /aarch64|arm64/i
    return windows.to_executable(framework, code, opts, fmt) if windows.respond_to?(:to_executable)

    nil
  end
end