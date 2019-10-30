##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder::Xor

  def initialize
    super(
      'Name'             => 'Single-byte XOR Countdown Encoder',
      'Description'      => %q{
        This encoder uses the length of the payload as a position-dependent
        encoder key to produce a small decoder stub.
      },
      'Author'           => 'vlad902',
      'Arch'             => ARCH_X86,
      'License'          => MSF_LICENSE,
      'Decoder'          =>
        {
          'BlockSize' => 1,
        })
  end

  #
  # Returns the decoder stub that is adjusted for the size of the buffer
  # being encoded.
  #
  def decoder_stub(state)

    # Sanity check that saved_registers doesn't overlap with modified_registers
    if (modified_registers & saved_registers).length > 0
      raise BadGenerateError
    end
    begin
      decoder =
        Rex::Arch::X86.set(
          Rex::Arch::X86::ECX,
          state.buf.length - 1,
          state.badchars) +
        "\xe8\xff\xff\xff" +  # call $+4
        "\xff\xc1" +          # inc ecx
        "\x5e" +              # pop esi
        "\x30\x4c\x0e\x07" +  # xor_loop: xor [esi + ecx + 0x07], cl
        "\xe2\xfa"            # loop xor_loop

      # Initialize the state context to 1
      state.context = 1
    rescue RuntimeError => e
      raise BadcharError if e.message == "No valid set instruction could be created!"
    end
    return decoder
  end

  #
  # Encodes a one byte block with the current index of the length of the
  # payload.
  #
  def encode_block(state, block)
    state.context += 1

    [ block.unpack('C')[0] ^ (state.context - 1) ].pack('C')
  end

  # Indicate that this module can preserve some registers
  def can_preserve_registers?
    true
  end

  # A list of registers always touched by this encoder
  def modified_registers
    [ Rex::Arch::X86::ECX, Rex::Arch::X86::ESI ]
  end

  # Convert the SaveRegisters to an array of x86 register constants
  def saved_registers
    Rex::Arch::X86.register_names_to_ids(datastore['SaveRegisters'])
  end
end
