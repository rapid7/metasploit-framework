# -*- coding: binary -*-
require 'rex/arch/x86'

module Rex
module Poly

###
#
# This class encapsulates logical registers for the X86 architecture.
#
###
class LogicalRegister::X86 < LogicalRegister

  #
  # The default set of register numbers that can be used on x86.
  #
  def self.regnum_set
    [
      Rex::Arch::X86::EAX,
      Rex::Arch::X86::EBX,
      Rex::Arch::X86::ECX,
      Rex::Arch::X86::EDX,
      Rex::Arch::X86::ESI,
      Rex::Arch::X86::EDI,
      Rex::Arch::X86::EBP,
      Rex::Arch::X86::ESP
    ]
  end

  #
  # Calls the base class constructor after translating the register name to
  # number.
  #
  def initialize(name, register = nil)
    super(name, register ? Rex::Arch::X86.reg_number(register) : nil)
  end

end

end
end
