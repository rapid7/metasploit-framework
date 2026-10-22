require 'msf/core/assembly/a_arch64'

#
# Linux aarch64 prepends
#
module Msf::Payload::Linux::Aarch64::Prepends
  include Msf::Payload::Linux::Prepends

  def prepends_order
    %w[PrependExecOnce PrependSetresuid PrependSetreuid PrependSetuid]
  end

  def appends_order
    %w[]
  end

  def prepends_map
    @prepends_map ||= {
      'PrependExecOnce' => prepend_exec_once,
      'PrependSetuid' => [
        Msf::Assembly::AArch64.instruction('mov', rt: 0, rm: 31), # mov x0, xzr
        Msf::Assembly::AArch64.instruction('mov', rt: 8, i16_5: 0x92), # mov x8, #0x92 (setuid)
        Msf::Assembly::AArch64.instruction('svc', i16_5: 0) # svc #0
      ].join,
      'PrependSetreuid' => [
        Msf::Assembly::AArch64.instruction('mov', rt: 0, rm: 31), # mov x0, xzr
        Msf::Assembly::AArch64.instruction('mov', rt: 1, rm: 31), # mov x1, xzr
        Msf::Assembly::AArch64.instruction('mov', rt: 8, i16_5: 0x91), # mov x8, #0x91 (setreuid)
        Msf::Assembly::AArch64.instruction('svc', i16_5: 0) # svc #0
      ].join,
      'PrependSetresuid' => [
        Msf::Assembly::AArch64.instruction('mov', rt: 0, rm: 31), # mov x0, xzr
        Msf::Assembly::AArch64.instruction('mov', rt: 1, rm: 31), # mov x1, xzr
        Msf::Assembly::AArch64.instruction('mov', rt: 2, rm: 31), # mov x2, xzr
        Msf::Assembly::AArch64.instruction('mov', rt: 8, i16_5: 0x93), # mov x8, #0x93 (setresuid)
        Msf::Assembly::AArch64.instruction('svc', i16_5: 0) # svc #0
      ].join
    }
  end

  def appends_map
    {}
  end

  private

  def prepend_exec_once
    return @prepend_exec_once if @prepend_exec_once

    marker = "#{prepend_exec_once_path}\x00".b
    marker_offset = 56
    payload_offset = aarch64_align_up(marker_offset + marker.bytesize, 4)
    instructions = [
      Msf::Assembly::AArch64.adr(instruction_address: 0, destination: marker_offset, register: 1), # adr x1, marker
      Msf::Assembly::AArch64.instruction('movn', rt: 0, il18_5: 99), # movn x0, #0x63 (AT_FDCWD)
      Msf::Assembly::AArch64.instruction('mov', rt: 2, i16_5: 0xc1), # mov x2, #0xc1 (O_WRONLY | O_CREAT | O_EXCL)
      Msf::Assembly::AArch64.instruction('mov', rt: 3, i16_5: 0x180), # mov x3, #0x180 (0600)
      Msf::Assembly::AArch64.instruction('mov', rt: 8, i16_5: 56), # mov x8, #56 (openat)
      Msf::Assembly::AArch64.instruction('svc', i16_5: 0), # svc #0
      Msf::Assembly::AArch64.instruction('subs', rt: 31, rn: 0, i12_10_s1: 0), # cmp x0, #0
      Msf::Assembly::AArch64.branch('blt', instruction_address: 28, destination: 44), # blt exit
      Msf::Assembly::AArch64.instruction('mov', rt: 8, i16_5: 57), # mov x8, #57 (close)
      Msf::Assembly::AArch64.instruction('svc', i16_5: 0), # svc #0
      Msf::Assembly::AArch64.branch('b', instruction_address: 40, destination: payload_offset, bits: 26, field: :i26_0), # b payload
      Msf::Assembly::AArch64.instruction('mov', rt: 0, i16_5: 0), # exit: mov x0, #0
      Msf::Assembly::AArch64.instruction('mov', rt: 8, i16_5: 93), # mov x8, #93 (exit)
      Msf::Assembly::AArch64.instruction('svc', i16_5: 0) # svc #0
    ]
    @prepend_exec_once = (instructions.join + marker).ljust(payload_offset, "\x00".b)
  end

  def aarch64_align_up(value, alignment)
    (value + alignment - 1) & -alignment
  end
end
