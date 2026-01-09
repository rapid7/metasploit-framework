module Msf::Util::EXE::Bsd
  def to_executable(framework, arch, code, opts = {}, fmt = 'elf')
    bsd = Object.new.extend(Msf::Util::EXE::Common)
    # bsd.extend(Msf::Util::EXE::Bsd::Common) BSD has no common module yet
    bsd.extend(Msf::Util::EXE::Bsd::X86) if arch =~ /x86|i386/i
    bsd.extend(Msf::Util::EXE::Bsd::X64) if arch =~ /x64|amd64/i
    return bsd.to_executable(framework, code, opts, fmt) if bsd.respond_to?(:to_executable)

    nil
  end
end