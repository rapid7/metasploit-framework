module Msf::Util::EXE::Solaris
  def to_executable(framework, arch, code, opts = {}, fmt = 'elf')
    solaris = Object.new.extend(Msf::Util::EXE::Common)
    # solaris.extend(Msf::Util::EXE::Solaris::Common) Solaris has no common module yet
    solaris.extend(Msf::Util::EXE::Solaris::X86) if arch =~ /x86|i386/i
    return solaris.to_executable(framework, code, opts, fmt) if solaris.respond_to?(:to_executable)
    nil
  end
end