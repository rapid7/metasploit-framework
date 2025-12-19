module Msf::Util::EXE::Solaris
  def to_executable(framework, arch, code, opts = {}, fmt = 'elf')
    return EXE::Solaris::X86.to_executable(framework, code, opts, fmt) if arch =~ /x86|i386/i
    nil
  end
end