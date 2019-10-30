##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# NOTE: Read this if you plan on using this encoder:
#
# This encoder has some limitations that must be considered.  First, this
# encoder cannot be used with all of the payloads included in the framework.
# Most notably, this includes windows/shell_reverse_tcp.  The reason for this
# is that some payloads are of a size that leads to a bad character (uppercase
# character) being generated in the decoder stub header.
#
# A second thing to consider is that some IP addresses used in payloads are
# incompatible with this encoder depending on their alignment within the
# payload.  For example, the use of 127.0.0.1 may not work due to the fact
# that it's impossible to reach the bytes 127, 0, and 1 in a single add or sub
# due to the algorithm that this encoder uses.
#
# Here's a description of how it works:
#
# This encoder is pretty lame.  It has a huge size overhead.  Alas, it
# does produce tolower safe and UTF8 safe payloads.  The decoder itself is
# split into three distinct chunks.  The first chunk is the header, the second
# chunk is the inline-decoding, and the third chunk is where the decoded data
# is persisted.  Unlike most encoders, this encoder does not use any branch
# instructions and instead runs into the decoded data after it completes due
# to the fact that it is decoding inline.
#
# The basic approach taken to implement the encoder is this.  First, the
# decoder header assumes that a register (ecx) points to the first byte
# in the decoder stub.  It then proceeds to calculate the offset to the
# third chunk of the decoder (the persisted data) and updates the context
# register (ecx) to point to the first byte of the third chunk of the decoder
# stub.  Following that, the second chunk of the decoder begins executing
# which uses a series of add or subtract operations on the third chunk of the
# decoder to produce the actual opcodes of the encoded payload.  For each four
# bytes of encoded data, a sub or add instruction is used in combination with
# complementary information stored in the third chunk of the decoder.
#
# For example, in order to produce 0x01fdfeff one could do the following:
#
#   0x5e096f7c
# - 0x5c0b707d
# ------------
#   0x01fdfeff
#
# After all of the inline decoding operations complete, the payload should
# simply fall through into the now-decoded payload that was stored in the
# third chunk of the decoder.
#
# The following is an example encoding of:
#
# "\xcc\x41\xcc\x41\xcc\x41\xcc\x41\xff\xfe\xfd\x01\xff\x02\x82\x4c"
#
# 00000000  6A04              push byte +0x4
# 00000002  6B3C240B          imul edi,[esp],byte +0xb
# 00000006  60                pusha
# 00000007  030C24            add ecx,[esp]
# 0000000A  6A11              push byte +0x11
# 0000000C  030C24            add ecx,[esp]
# 0000000F  6A04              push byte +0x4
# 00000011  68640F5F31        push dword 0x315f0f64
# 00000016  5F                pop edi
# 00000017  0139              add [ecx],edi
# 00000019  030C24            add ecx,[esp]
# 0000001C  6870326B32        push dword 0x326b3270
# 00000021  5F                pop edi
# 00000022  0139              add [ecx],edi
# 00000024  030C24            add ecx,[esp]
# 00000027  687D700B5C        push dword 0x5c0b707d
# 0000002C  5F                pop edi
# 0000002D  2939              sub [ecx],edi
# 0000002F  030C24            add ecx,[esp]
# 00000032  6804317F32        push dword 0x327f3104
# 00000037  5F                pop edi
# 00000038  2939              sub [ecx],edi
# 0000003A  030C24            add ecx,[esp]
# 0000003D  68326D105C        push dword 0x5c106d32
# 00000042  0F610F            punpcklwd mm1,[edi]
# 00000045  7C6F              jl 0xb6
# 00000047  095E03            or [esi+0x3],ebx
# 0000004A  3401              xor al,0x1
# 0000004C  7F                db 0x7F
#
class MetasploitModule < Msf::Encoder

  # This encoder has a manual ranking because it should only be used in cases
  # where information has been explicitly supplied, like the BufferOffset.
  Rank = ManualRanking

  def initialize
    super(
      'Name'             => 'Avoid UTF8/tolower',
      'Description'      => 'UTF8 Safe, tolower Safe Encoder',
      'Author'           => 'skape',
      'Arch'             => ARCH_X86,
      'License'          => MSF_LICENSE,
      'EncoderType'      => Msf::Encoder::Type::NonUpperUtf8Safe,
      'Decoder'          =>
        {
          'KeySize'    => 4,
          'BlockSize'  => 4,
        })
  end

  #
  # Returns the decoder stub that is adjusted for the size of
  # the buffer being encoded
  #
  def decoder_stub(state)
    len = ((state.buf.length + 3) & (~0x3)) / 4

    # Grab the number of additional bytes that we need to adjust by in order
    # to get the context register to point immediately after the stub header
    off = (datastore['BufferOffset'] || 0).to_i

    # Check to make sure that the length is a valid size
    if is_badchar(state, len)
      raise EncodingError.new("The payload being encoded is of an incompatible size (#{len} bytes)")
    end

    decoder =
      "\x6a" + [len].pack('C')      +  # push len
      "\x6b\x3c\x24\x0b"            +  # imul 0xb
      "\x60"                        +  # pusha
      "\x03\x0c\x24"                +  # add ecx, [esp]
      "\x6a" + [0x11+off].pack('C') +  # push byte 0x11 + off
      "\x03\x0c\x24"                +  # add ecx, [esp]
      "\x6a\x04"                       # push byte 0x4

    # encoded sled
    state.context = ''

    return decoder
  end

  def encode_block(state, block)
    buf = try_add(state, block)

    if (buf.nil?)
      buf = try_sub(state, block)
    end

    if (buf.nil?)
      raise BadcharError.new(state.encoded, 0, 0, 0)
    end

    buf
  end

  #
  # Appends the encoded context portion.
  #
  def encode_end(state)
    state.encoded += state.context
  end

  #
  # Generate the instructions that will be used to produce a valid
  # block after decoding using the sub instruction in conjunction with
  # two UTF8/tolower safe values.
  #
  def try_sub(state, block)
    buf   = "\x68";
    vbuf  = ''
    ctx   = ''
    carry = 0

    block.each_byte { |b|
      # It's impossible to reach 0x7f, 0x80, 0x81 with two subs
      # of a value that is < 0x80 without NULLs.
      return nil if (b == 0x80 or b == 0x81 or b == 0x7f)

      x          = 0
      y          = 0
      attempts   = 0
      prev_carry = carry

      begin
        carry = prev_carry

        if (b > 0x80)
          diff  = 0x100 - b
          y     = rand(0x80 - diff - 1).to_i + 1
          x     = (0x100 - (b - y + carry))
          carry = 1
        else
          diff  = 0x7f - b
          x     = rand(diff - 1) + 1
          y     = (b + x + carry) & 0xff
          carry = 0
        end

        attempts += 1

        # Lame.
        return nil if (attempts > 512)

      end while (is_badchar(state, x) or is_badchar(state, y))

      vbuf += [x].pack('C')
      ctx  += [y].pack('C')
    }

    buf += vbuf + "\x5f\x29\x39\x03\x0c\x24"

    state.context += ctx

    return buf

  end

  #
  # Generate instructions that will be used to produce a valid block after
  # decoding using the add instruction in conjunction with two UTF8/tolower
  # safe values.
  #
  def try_add(state, block)
    buf  = "\x68"
    vbuf = ''
    ctx  = ''

    block.each_byte { |b|
      # It's impossible to produce 0xff and 0x01 using two non-NULL,
      # tolower safe, and UTF8 safe values.
      return nil if (b == 0xff or b == 0x01 or b == 0x00)

      attempts = 0

      begin
        xv = rand(b - 1) + 1

        attempts += 1

        # Lame.
        return nil if (attempts > 512)

      end while (is_badchar(state, xv) or is_badchar(state, b - xv))

      vbuf += [xv].pack('C')
      ctx  += [b - xv].pack('C')
    }

    buf += vbuf + "\x5f\x01\x39\x03\x0c\x24"

    state.context += ctx

    return buf
  end

  def is_badchar(state, val)
    ((val >= 0x41 and val <= 0x5a) or val >= 0x80) or Rex::Text.badchar_index([val].pack('C'), state.badchars)
  end
end
