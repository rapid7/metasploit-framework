# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder::Xor

  Rank = LowRanking

  def initialize
    super(
      'Name' => 'Dword XOR Encoder (Tag-based)',
      'Description' => %q{
        Dword XOR encoder for RISC-V 32-bit (Little Endian) using a
        tag-based terminator rather than an encoded length. The decoder
        loop XORs each dword and stops when the result is zero (the
        sentinel). This avoids encoding the payload length in the stub,
        eliminating a source of bad character conflicts.

        Note: payloads containing 4-byte aligned zero dwords will cause
        early loop termination due to collision with the sentinel value.
      },
      'Author' => ['bcoles'],
      'Arch' => ARCH_RISCV32LE,
      'License' => MSF_LICENSE,
      'Decoder' => {
        'KeySize' => 4,
        'BlockSize' => 4,
        'KeyPack' => 'V'
      }
    )
  end

  #
  # Returns the decoder stub that is adjusted for the size of
  # the buffer being encoded.
  #
  def decoder_stub(state)
    if state.badchars.to_s.include?("\x00".b)
      raise EncodingError, 'The RISC-V decoder stub inherently contains null bytes (auipc, ecall)'
    end

    raise EncodingError, 'The payload is empty' if state.buf.empty?
    raise EncodingError, "The payload is not aligned to 4 bytes (#{state.buf.length} bytes)" if (state.buf.length % 4) != 0

    # The sentinel-based loop terminates when a decoded dword is zero.
    # A zero dword in the raw payload will always decode to zero regardless
    # of the key, causing early termination. Detect this upfront.
    state.buf.scan(/.{4}/m).each_with_index do |block, idx|
      if block.unpack1('V') == 0
        raise EncodingError, "Payload contains a zero dword at offset #{idx * 4}; use riscv32le/longxor instead"
      end
    end

    # Decoder stub layout (64 bytes = 15 instructions + 4-byte key):
    #
    #   0x00: auipc  t0, 0             # t0 = address of this instruction
    #   0x04: lw     t1, 60(t0)        # t1 = XOR key (stored at end of stub)
    #   0x08: addi   t4, t0, 64        # t4 = start of encoded payload
    #   0x0c: addi   t0, t4, 0         # t0 = working pointer
    #   0x10: lw     t3, 0(t0)         # load encoded dword
    #   0x14: xor    t3, t3, t1        # XOR with key
    #   0x18: sw     t3, 0(t0)         # store decoded dword
    #   0x1c: addi   t0, t0, 4         # advance pointer
    #   0x20: bne    t3, x0, -0x10     # loop to 0x10 if non-zero (sentinel = 0)
    #   0x24: addi   a0, t4, 0         # cache flush start address
    #   0x28: addi   a1, t0, 0         # cache flush end address
    #   0x2c: addi   a2, x0, 0         # flags (0 = all harts)
    #   0x30: addi   a7, x0, 259       # __NR_riscv_flush_icache
    #   0x34: ecall                    # flush icache
    #   0x38: jalr   x0, t4, 0         # jump to decoded payload
    #   0x3c: <4-byte XOR key>
    #
    decoder = [
      0x00000297,                     # auipc  t0, 0
      encode_lw(6, 5, 60),            # lw     t1, 60(t0)
      encode_addi(29, 5, 64),         # addi   t4, t0, 64
      encode_addi(5, 29, 0),          # addi   t0, t4, 0
      encode_lw(28, 5, 0),            # lw     t3, 0(t0)
      encode_xor(28, 28, 6),          # xor    t3, t3, t1
      encode_sw(28, 5, 0),            # sw     t3, 0(t0)
      encode_addi(5, 5, 4),           # addi   t0, t0, 4
      encode_bne(28, 0, -16),         # bne    t3, x0, loop
      encode_addi(10, 29, 0),         # addi   a0, t4, 0
      encode_addi(11, 5, 0),          # addi   a1, t0, 0
      encode_addi(12, 0, 0),          # addi   a2, x0, 0
      encode_addi(17, 0, 259),        # addi   a7, x0, 259
      0x00000073,                     # ecall
      encode_jalr(0, 29, 0),          # jalr   x0, t4, 0
    ].pack('V*')

    state.decoder_key_offset = decoder.length
    decoder + "\x00\x00\x00\x00".b
  end

  #
  # Append the XOR key as a sentinel after the encoded payload.
  # When the decoder XORs this with the key, the result is zero,
  # terminating the decode loop.
  #
  def encode_end(state)
    state.encoded += [state.key.to_i].pack('V')
  end

  private

  # I-type: ADDI rd, rs1, imm12
  def encode_addi(rd, rs1, imm12)
    ((imm12 & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | 0b0010011
  end

  # I-type: LW rd, imm12(rs1)
  def encode_lw(rd, rs1, imm12)
    ((imm12 & 0xfff) << 20) | (rs1 << 15) | (0b010 << 12) | (rd << 7) | 0b0000011
  end

  # S-type: SW rs2, imm12(rs1)
  def encode_sw(rs2, rs1, imm12)
    imm = imm12 & 0xfff
    (((imm >> 5) & 0x7f) << 25) | (rs2 << 20) | (rs1 << 15) | (0b010 << 12) | ((imm & 0x1f) << 7) | 0b0100011
  end

  # R-type: XOR rd, rs1, rs2
  def encode_xor(rd, rs1, rs2)
    (rs2 << 20) | (rs1 << 15) | (0b100 << 12) | (rd << 7) | 0b0110011
  end

  # B-type: BNE rs1, rs2, offset
  def encode_bne(rs1, rs2, offset)
    imm = offset & 0x1fff
    bit12 = (imm >> 12) & 1
    bit11 = (imm >> 11) & 1
    hi6 = (imm >> 5) & 0x3f
    lo4 = (imm >> 1) & 0xf
    (bit12 << 31) | (hi6 << 25) | (rs2 << 20) | (rs1 << 15) |
      (0b001 << 12) | (lo4 << 8) | (bit11 << 7) | 0b1100011
  end

  # I-type: JALR rd, rs1, imm12
  def encode_jalr(rd, rs1, imm12)
    ((imm12 & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | 0b1100111
  end
end
