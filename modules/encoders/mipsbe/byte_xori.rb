##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasm'

class MetasploitModule < Msf::Encoder::Xor
  Rank = NormalRanking

  def initialize
    super(
      'Name'             => 'Byte XORi Encoder',
      'Description'      => %q{
        Mips Web server exploit friendly xor encoder. This encoder has been found useful on
        situations where '&' (0x26) is a badchar. Since 0x26 is the xor's opcode on MIPS
        architectures, this one is based on the xori instruction.
      },
      'Author'           =>
        [
          'Julien Tinnes <julien[at]cr0.org>', # original longxor encoder, which this one is based on
          'juan vazquez' # byte_xori encoder
        ],
      'Arch'             => ARCH_MIPSBE,
      'License'          => MSF_LICENSE,
      'Decoder'          =>
        {
          'KeySize'   => 1,
          'BlockSize' => 1,
          'KeyPack'   => 'C',
        })
  end

  #
  # Returns the decoder stub that is adjusted for the size of the buffer
  # being encoded.
  #
  def decoder_stub(state)

    # add 4 number of passes  for the space reserved for the key, at the end of the decoder stub
    # (see commented source)
    number_of_passes=state.buf.length+4
    raise EncodingError.new("The payload being encoded is too long (#{state.buf.length} bytes)") if number_of_passes > 32766

    # 16-bits not (again, see also commented source)
    reg_14 = (number_of_passes+1)^0xFFFF

    decoder = Metasm::Shellcode.assemble(Metasm::MIPS.new(:big), <<EOS).encoded.data
main:

li macro reg, imm
  addiu reg, $0, imm                     ; 0x24xxyyyy - xx: reg #, yyyy: imm # imm must be equal or less than 0x7fff
endm

  li      ($14, #{reg_14})               ; 0x240exxxx - store in $14 the number of passes (two's complement) - xxxx (number of passes)
  nor     $14, $14, $0                   ; 0x01c07027 - get in $14 the number of passes
  li      ($11,-69)                      ; 0x240bffbb - store in $11 the offset to the end of the decoder (two's complement) (from the addu instr)

; acts as getpc
next:
  bltzal  $8, next                       ; 0x0510ffff - branch to next if $8 < 0, store return address in $31 ($ra); pipelining executes next instr.
  slti    $8, $0, 0x#{slti_imm(state)}   ; 0x2808xxxx - Set $8 = 0; Set $8 = 1 if $0 < imm; else $8 = 0 / xxxx: imm

  nor     $11, $11, $0                   ; 0x01605827 - get in $11 the offset to the end of the decoder (from the addu instr)
  addu    $25, $31, $11                  ; 0x03ebc821 - get in $25 a pointer to the end of the decoder stub

  slti    $23, $0, 0x#{slti_imm(state)}  ; 0x2817xxxx - Set $23 = 0 (Set $23 = 1 if $0 < imm; else $23 = 0) / xxxx: imm
  lb      $17, -1($25)                   ; 0x8f31fffc - Load xor key in $17 (stored on the last byte of the decoder stub)

; Init $6 and $15
  li      ($13, -4)                      ; 0x240dfffc - $13 = -4
  nor     $6, $13, $0                    ; 0x01a03027 - $6 = 3 ; used to easily get the cacheflush parameter
  addi    $15, $6, -2                    ; 0x20cffffe - $15 = 1 ($15 = decoding loop counter increment)

; In order avoid null bytes, decode also the xor key, so memory can be
; referenced with offset -1
loop:
  lb      $8, -4($25)                    ; 0x8f28fffc - Load in $8 the byte to decode
  addu    $23, $23, $15                  ; 0x02efb821 - Increment the counter ($23)
  xori    $3, $8, 0x#{padded_key(state)} ; 0x01111826 - xori decoding instruction, store the decoded byte on $3
  #{set_on_less_than(state)}             ; 0x02eef0xx - $30 = 1 if $23 < $14; else $30 = 0 (update branch condition) / xx: 0x2b if slti, 0x2a if slt
  sb      $3, -4($25)                    ; 0xaf23fffc - Store decoded byte on memory
  bne     $0, $30, loop                  ; 0x17c0fff9 - branch to loop if $30 != 0 (ranch while bytes to decode)
  addu    $25, $25, $15                  ; 0x032dc821 - next instruction to decode, executed because of the pipelining

  li      ($2, 4147)                     ; 0x24021033 - cacheflush sytem call
  syscall 0x52950                        ; 0x014a540c
  nop                                    ; encoded shellcoded must be here (xor key right here ;) after decoding will result in a nop
EOS

    return decoder
  end


  def padded_key(state, size=1)
    key = Rex::Text.rand_text(size, state.badchars)
    key << [state.key].pack("C")
    return key.unpack("n")[0].to_s(16)
  end

  # Returns an two-bytes immediate value without badchars. The value must be
  # on the 0x8000-0x8fff so it is used as negative value by slti (set less
  # than signed immediate)
  def slti_imm(state)
    imm = Rex::Text.rand_text(2, state.badchars + (0x00..0x7f).to_a.pack("C*"))
    return imm.unpack("n")[0].to_s(16)
  end

  # Since 0x14 contains the number of passes, and because of the li macro, can't be
  # longer than 0x7fff, both sltu (unsigned) and slt (signed) operations can be used
  # here
  def set_on_less_than(state)
    instructions = {
      "sltu   $30, $23, $14" => "\x02\xee\xf0\x2b", # set less than unsigned
      "slt    $30, $23, $14" => "\x02\xee\xf0\x2a"  # set less than
    }

    instructions.each do |k,v|
      if Rex::Text.badchar_index(v, state.badchars) == nil
        return k
      end
    end

    raise BadcharError.new,
          "The #{self.name} encoder failed to encode the decoder stub without bad characters.",
          caller
  end

  def encode_finalize_stub(state, stub)
    # Including the key into the stub by ourselves because it should be located
    # in the last 4 bytes of the decoder stub. In this way decoding will convert
    # these bytes into a nop instruction (0x00000000). The Msf::Encoder only supports
    # one decoder_key_offset position
    real_key = state.key
    stub[-4, state.decoder_key_size] = [ real_key.to_i ].pack(state.decoder_key_pack)
    stub[-3, state.decoder_key_size] = [ real_key.to_i ].pack(state.decoder_key_pack)
    stub[-2, state.decoder_key_size] = [ real_key.to_i ].pack(state.decoder_key_pack)
    stub[-1, state.decoder_key_size] = [ real_key.to_i ].pack(state.decoder_key_pack)
    return stub
  end
end
