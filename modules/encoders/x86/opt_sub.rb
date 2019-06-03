##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder
  Rank = ManualRanking

  ASM_SUBESP20 = "\x83\xEC\x20"

  SET_ALPHA    = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
  SET_SYM      = '!@#$%^&*()_+\\-=[]{};\'":<>,.?/|~'
  SET_NUM      = '0123456789'
  SET_FILESYM  = '()_+-=\\/.,[]{}@!$%^&='

  CHAR_SET_ALPHA         = SET_ALPHA + SET_SYM
  CHAR_SET_ALPHANUM      = SET_ALPHA + SET_NUM + SET_SYM
  CHAR_SET_FILEPATH      = SET_ALPHA + SET_NUM + SET_FILESYM

  def initialize
    super(
      'Name'             => 'Sub Encoder (optimised)',
      'Description'      => %q{
        Encodes a payload using a series of SUB instructions and writing the
        encoded value to ESP. This concept is based on the known SUB encoding
        approach that is widely used to manually encode payloads with very
        restricted allowed character sets. It will not reset EAX to zero unless
        absolutely necessary, which helps reduce the payload by 10 bytes for
        every 4-byte chunk. ADD support hasn't been included as the SUB
        instruction is more likely to avoid bad characters anyway.

        The payload requires a base register to work off which gives the start
        location of the encoder payload in memory. If not specified, it defaults
        to ESP. If the given register doesn't point exactly to the start of the
        payload then an offset value is also required.

        Note: Due to the fact that many payloads use the FSTENV approach to
        get the current location in memory there is an option to protect the
        start of the payload by setting the 'OverwriteProtect' flag to true.
        This adds 3-bytes to the start of the payload to bump ESP by 32 bytes
        so that it's clear of the top of the payload.
      },
      'Author'           => 'OJ Reeves <oj[at]buffered.io>',
      'Arch'             => ARCH_X86,
      'License'          => MSF_LICENSE,
      'Decoder'          => { 'BlockSize'  => 4 }
    )

    register_options(
      [
        OptString.new( 'ValidCharSet', [ false, "Specify a known set of valid chars (ALPHA, ALPHANUM, FILEPATH)" ]),
        OptBool.new( 'OverwriteProtect', [ false, "Indicate if the encoded payload requires protection against being overwritten", false])
      ],
      self.class)
  end

  #
  # Conver the shellcode into a set of 4-byte chunks that can be
  # encoding while making sure it is 4-byte aligned.
  #
  def prepare_shellcode(sc, protect_payload)
    # first instructions need to be ESP offsetting if the payload
    # needs to be protected
    sc = ASM_SUBESP20 + sc if protect_payload == true

    # first of all we need to 4-byte align the payload if it
    # isn't already aligned, by prepending NOPs.
    rem = sc.length % 4
    sc = @asm['NOP'] * (4 - rem) + sc if rem != 0

    # next we break it up into 4-byte chunks, convert to an unsigned
    # int block so calculations are easy
    chunks = []
    sc = sc.bytes.to_a
    while sc.length > 0
      chunk = sc.shift + (sc.shift << 8) + (sc.shift << 16) + (sc.shift << 24)
      chunks << chunk
    end

    # return the array in reverse as this is the order the instructions
    # will be written to the stack.
    chunks.reverse
  end

  #
  # From the list of characters given, find two bytes that when
  # ANDed together result in 0. Returns nil if not found.
  #
  def find_opposite_bytes(list)
    list.each_char do |b1|
      list.each_char do |b2|
        if b1.ord & b2.ord == 0
          return (b1 * 4), (b2 * 4)
        end
      end
    end
    return nil, nil
  end

  #
  # Entry point to the decoder.
  #
  def decoder_stub(state)
    return state.decoder_stub if state.decoder_stub

    # configure our instruction dictionary
    @asm = {
      'NOP' => "\x90",
      'AND' => { 'EAX' => "\x25" },
      'SUB' => { 'EAX' => "\x2D" },
      'PUSH' => {
        'EBP' => "\x55", 'ESP' => "\x54",
        'EAX' => "\x50", 'EBX' => "\x53",
        'ECX' => "\x51", 'EDX' => "\x52",
        'EDI' => "\x57", 'ESI' => "\x56"
      },
      'POP' => { 'ESP' => "\x5C", 'EAX' => "\x58", }
    }

    # set up our base register, defaulting to ESP if not specified
    @base_reg = (datastore['BufferRegister'] || 'ESP').upcase

    # determine the required bytes
    @required_bytes =
      @asm['AND']['EAX']  +
      @asm['SUB']['EAX']  +
      @asm['PUSH']['EAX'] +
      @asm['POP']['ESP']  +
      @asm['POP']['EAX']  +
      @asm['PUSH'][@base_reg]

    # generate a sorted list of valid characters
    char_set = ""
    case (datastore['ValidCharSet'] || "").upcase
    when 'ALPHA'
      char_set = CHAR_SET_ALPHA
    when 'ALPHANUM'
      char_set = CHAR_SET_ALPHANUM
    when 'FILEPATH'
      char_set = CHAR_SET_FILEPATH
    else
      for i in 0 .. 255
        char_set += i.chr.to_s
      end
    end

    # remove any bad chars and populate our valid chars array.
    @valid_chars = ""
    char_set.each_char do |c|
      @valid_chars << c.to_s unless state.badchars.include?(c.to_s)
    end

    # we need the valid chars sorted because of the algorithm we use
    @valid_chars = @valid_chars.chars.sort.join
    @valid_bytes = @valid_chars.bytes.to_a

    all_bytes_valid = @required_bytes.bytes.reduce(true) { |a, byte| a && @valid_bytes.include?(byte) }

    # determine if we have any invalid characters that we rely on.
    unless all_bytes_valid
      raise EncodingError, "Bad character set contains characters that are required for this encoder to function."
    end

    unless @asm['PUSH'][@base_reg]
      raise EncodingError, "Invalid base register"
    end

    # get the offset from the specified base register, or default to zero if not specifed
    reg_offset = (datastore['BufferOffset'] || 0).to_i

    # calculate two opposing values which we can use for zeroing out EAX
    @clear1, @clear2 = find_opposite_bytes(@valid_chars)

    # if we can't then we bomb, because we know we need to clear out EAX at least once
    unless @clear1
      raise EncodingError, "Unable to find AND-able chars resulting 0 in the valid character set."
    end

    # with everything set up, we can now call the encoding routine
    state.decoder_stub = encode_payload(state.buf, reg_offset, datastore['OverwriteProtect'])

    state.buf = ""
    state.decoder_stub
  end

  #
  # Determine the bytes, if any, that will result in the given chunk
  # being decoded using SUB instructions from the previous EAX value
  #
  def sub_3(chunk, previous)
    carry = 0
    shift = 0
    target = previous - chunk
    sum = [0, 0, 0]

    4.times do |idx|
      b = (target >> shift) & 0xFF
      lo = md = hi = 0

      # keep going through the character list under the "lowest" valid
      # becomes too high (ie. we run out)
      while lo < @valid_bytes.length
        # get the total of the three current bytes, including the carry from
        # the previous calculation
        total = @valid_bytes[lo] + @valid_bytes[md] + @valid_bytes[hi] + carry

        # if we matched a byte...
        if (total & 0xFF) == b
          # store the carry for the next calculation
          carry = (total >> 8) & 0xFF

          # store the values in the respective locations
          sum[2] |= @valid_bytes[lo] << shift
          sum[1] |= @valid_bytes[md] << shift
          sum[0] |= @valid_bytes[hi] << shift
          break
        end

        hi += 1
        if hi >= @valid_bytes.length
          md += 1
          hi = md
        end

        if md >= @valid_bytes.length
          lo += 1
          hi = md = lo
        end
      end

      # we ran out of chars to try
      if lo >= @valid_bytes.length
        return nil, nil
      end

      shift += 8
    end

    return sum, chunk
  end

  #
  # Helper that writes instructions to zero out EAX using two AND instructions.
  #
  def zero_eax
    data = ""
    data << @asm['AND']['EAX']
    data << @clear1
    data << @asm['AND']['EAX']
    data << @clear2
    data
  end

  #
  # Write instructions that perform the subtraction using the given encoded numbers.
  #
  def create_sub(encoded)
    data = ""
    encoded.each do |e|
      data << @asm['SUB']['EAX']
      data << [e].pack("L")
    end
    data << @asm['PUSH']['EAX']
    data
  end

  #
  # Encoding the specified payload buffer.
  #
  def encode_payload(buf, reg_offset, protect_payload)
    data = ""

    # prepare the shellcode for munging
    chunks = prepare_shellcode(buf, protect_payload)

    # start by reading the value from the base register and dropping it into EAX for munging
    data << @asm['PUSH'][@base_reg]
    data << @asm['POP']['EAX']

    # store the offset of the stubbed placeholder
    base_reg_offset = data.length

    # Write out a stubbed placeholder for the offset instruction based on
    # the base register, we'll update this later on when we know how big our payload is.
    encoded, _ = sub_3(0, 0)
    raise EncodingError, "Couldn't offset base register." if encoded.nil?
    data << create_sub(encoded)

    # finally push the value of EAX back into ESP
    data << @asm['PUSH']['EAX']
    data << @asm['POP']['ESP']

    # start instruction encoding from a clean slate
    data << zero_eax

    # keep track of the previous instruction, because we use that as the starting point
    # for the next instruction, which saves us 10 bytes per 4 byte block. If we can't
    # offset correctly, we zero EAX and try again.
    previous = 0
    chunks.each do |chunk|
      encoded, previous = sub_3(chunk, previous)

      if encoded.nil?
        # try again with EAX zero'd out
        data << zero_eax
        encoded, previous = sub_3(chunk, 0)
      end

      # if we're still nil here, then we have an issue
      raise EncodingError, "Couldn't encode payload" if encoded.nil?

      data << create_sub(encoded)
    end

    # Now that the entire payload has been generated, we figure out offsets
    # based on sizes so that the payload overlaps perfectly with the end of
    # our decoder
    total_offset = reg_offset + data.length + (chunks.length * 4) - 1
    encoded, _ = sub_3(total_offset, 0)

    # if we're still nil here, then we have an issue
    raise EncodingError, "Couldn't encode protection" if encoded.nil?
    patch = create_sub(encoded)

    # patch in the correct offset back at the start of our payload
    data[base_reg_offset .. base_reg_offset + patch.length] = patch

    # and we're done finally!
    data
  end
end

