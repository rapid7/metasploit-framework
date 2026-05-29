# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder::Xor

  Rank = NormalRanking

  def initialize
    super(
      'Name' => 'XOR Encoder with Cipher Feedback',
      'Description' => %q{
        Dword XOR encoder with cipher feedback for RISC-V 32-bit
        (Little Endian). Each dword is XORed with the previous encoded
        dword rather than a static key, creating a chained dependency
        that makes the output more resistant to frequency analysis. The
        first dword is XORed with the key to bootstrap the chain.
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

    block_count = state.buf.length / 4
    raise EncodingError, "The payload being encoded is too long (#{state.buf.length} bytes)" if block_count > 2047
    raise EncodingError, "The payload is not aligned to 4 bytes (#{state.buf.length} bytes)" if (state.buf.length % 4) != 0

    # Decoder stub layout (76 bytes = 18 instructions + 4-byte key):
    #
    #   0x00: auipc  t0, 0             # t0 = address of this instruction
    #   0x04: addi   t4, t0, 76        # t4 = start of encoded payload
    #   0x08: lw     t1, 72(t0)        # t1 = feedback value (initially the key)
    #   0x0c: addi   t2, x0, count     # t2 = number of dwords to decode
    #   0x10: addi   t0, t4, 0         # t0 = working pointer
    #   0x14: lw     t5, 0(t0)         # load encoded dword into t5
    #   0x18: xor    t3, t5, t1        # decoded = encoded XOR feedback
    #   0x1c: sw     t3, 0(t0)         # store decoded dword
    #   0x20: addi   t1, t5, 0         # feedback = previous encoded dword
    #   0x24: addi   t0, t0, 4         # advance pointer
    #   0x28: addi   t2, t2, -1        # decrement counter
    #   0x2c: bne    t2, x0, -0x18     # loop to 0x14
    #   0x30: addi   a0, t4, 0         # cache flush start address
    #   0x34: addi   a1, t0, 0         # cache flush end address
    #   0x38: addi   a2, x0, 0         # flags (0 = all harts)
    #   0x3c: addi   a7, x0, 259       # __NR_riscv_flush_icache
    #   0x40: ecall                    # flush icache
    #   0x44: jalr   x0, t4, 0         # jump to decoded payload
    #   0x48: <4-byte XOR key>
    #
    decoder = [
      0x00000297,                     # auipc  t0, 0
      encode_addi(29, 5, 76),         # addi   t4, t0, 76
      encode_lw(6, 5, 72),            # lw     t1, 72(t0)
      encode_addi(7, 0, block_count), # addi   t2, x0, count
      encode_addi(5, 29, 0),          # addi   t0, t4, 0
      encode_lw(30, 5, 0),            # lw     t5, 0(t0)
      encode_xor(28, 30, 6),          # xor    t3, t5, t1
      encode_sw(28, 5, 0),            # sw     t3, 0(t0)
      encode_addi(6, 30, 0),          # addi   t1, t5, 0
      encode_addi(5, 5, 4),           # addi   t0, t0, 4
      encode_addi(7, 7, -1),          # addi   t2, t2, -1
      encode_bne(7, 0, -24),          # bne    t2, x0, loop
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
  # Initialize the feedback value prior to encoding.
  #
  def encode_begin(state)
    @feedback = state.key.to_i
  end

  #
  # Encode a block using XOR with cipher feedback. Each encoded
  # dword becomes the XOR operand for the next block.
  #
  def encode_block(_state, block)
    encoded_val = block.unpack1('V') ^ @feedback
    @feedback = encoded_val
    [encoded_val].pack('V')
  end

  #
  # Verify that a candidate key remains valid once cipher feedback
  # encoding has been applied across the full buffer.
  #
  def find_key_verify(buf, key_bytes, badchars)
    return false unless super
    return true if badchars.to_s.empty?

    feedback = key_bytes_to_integer(key_bytes)

    buf.bytes.each_slice(4) do |bytes|
      block = bytes.pack('C*').ljust(4, "\x00".b)
      encoded_val = block.unpack1('V') ^ feedback
      return false unless has_badchars?([encoded_val].pack('V'), badchars).nil?

      feedback = encoded_val
    end

    true
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
