module Msf::Util::EXE::Solaris
  include Msf::Util::EXE::Common
  include Msf::Util::EXE::Solaris::X86

  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    def to_executable_solaris(framework, arch, code, fmt = 'elf', opts = {})
      return to_executable_solaris_x86(framework, code, fmt, opts) if arch.index(ARCH_X86)
    end

    def to_executable_solaris_x86(framework, code, fmt = 'elf', opts = {})
      return to_solaris_x86_elf(framework, code, opts) if fmt == 'elf'
    end
  end

  class << self
    include ClassMethods
  end
end
