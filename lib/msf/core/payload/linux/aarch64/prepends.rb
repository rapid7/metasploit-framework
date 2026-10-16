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
        aarch64_instruction('mov', rt: 0, rm: 31),
        aarch64_instruction('mov', rt: 8, i16_5: 0x92),
        aarch64_instruction('svc', i16_5: 0)
      ].join,
      'PrependSetreuid' => [
        aarch64_instruction('mov', rt: 0, rm: 31),
        aarch64_instruction('mov', rt: 1, rm: 31),
        aarch64_instruction('mov', rt: 8, i16_5: 0x91),
        aarch64_instruction('svc', i16_5: 0)
      ].join,
      'PrependSetresuid' => [
        aarch64_instruction('mov', rt: 0, rm: 31),
        aarch64_instruction('mov', rt: 1, rm: 31),
        aarch64_instruction('mov', rt: 2, rm: 31),
        aarch64_instruction('mov', rt: 8, i16_5: 0x93),
        aarch64_instruction('svc', i16_5: 0)
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
      aarch64_adr(marker_offset),
      aarch64_instruction('movn', rt: 0, il18_5: 99),
      aarch64_instruction('mov', rt: 2, i16_5: 0xc1),
      aarch64_instruction('mov', rt: 3, i16_5: 0x180),
      aarch64_instruction('mov', rt: 8, i16_5: 56),
      aarch64_instruction('svc', i16_5: 0),
      aarch64_instruction('subs', rt: 31, rn: 0, i12_10_s1: 0),
      aarch64_branch('blt', 28, 44),
      aarch64_instruction('mov', rt: 8, i16_5: 57),
      aarch64_instruction('svc', i16_5: 0),
      aarch64_branch('b', 40, payload_offset, bits: 26, field: :i26_0),
      aarch64_instruction('mov', rt: 0, i16_5: 0),
      aarch64_instruction('mov', rt: 8, i16_5: 93),
      aarch64_instruction('svc', i16_5: 0)
    ]
    @prepend_exec_once = (instructions.join + marker).ljust(payload_offset, "\x00".b)
  end

  def aarch64_adr(destination)
    immediate = destination
    encoded = ((immediate & 3) << 29) | (((immediate >> 2) & 0x7ffff) << 5)
    aarch64_instruction('adr', rt: 1, i19_5_2_29: encoded)
  end

  def aarch64_branch(name, instruction_address, destination, bits: 19, field: :i19_5)
    displacement = destination - instruction_address
    raise Metasm::EncodeError, 'AArch64 branch destination is not instruction-aligned' unless (displacement % 4).zero?

    immediate = displacement / 4
    minimum = -(1 << (bits - 1))
    maximum = (1 << (bits - 1)) - 1
    raise Metasm::EncodeError, 'AArch64 branch destination is too far away' unless immediate.between?(minimum, maximum)

    aarch64_instruction(name, **{ field => immediate })
  end

  def aarch64_instruction(name, **fields)
    opcode = aarch64_processor.opcode_list_byname.fetch(name).find do |candidate|
      candidate.args == fields.keys && !candidate.props[:r_32] && !candidate.props[:mem_incr]
    end
    raise Metasm::EncodeError, "Unsupported AArch64 instruction: #{name}" unless opcode

    word = fields.reduce(opcode.bin) do |encoded, (field, value)|
      mask, shift = opcode.fields.fetch(field)
      encoded | ((value & mask) << shift)
    end
    [word].pack('V')
  end

  def aarch64_processor
    @aarch64_processor ||= Metasm::ARM64.new
  end

  def aarch64_align_up(value, alignment)
    (value + alignment - 1) & -alignment
  end
end
