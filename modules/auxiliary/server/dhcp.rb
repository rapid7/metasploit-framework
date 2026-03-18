##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DHCPServer

  def initialize
    super(
      'Name' => 'DHCP Server',
      'Description' => %q{
        This module provides a DHCP service
      },
      'Author' => [ 'scriptjunkie', 'apconole[at]yahoo.com' ],
      'License' => MSF_LICENSE,
      'Actions' => [
        [ 'Service', 'Description' => 'Run DHCP server' ]
      ],
      'PassiveActions' => [
        'Service'
      ],
      'DefaultAction' => 'Service'
    )
  end

  def run
    start_service(datastore)

    # Wait for finish
    sleep 2 while @dhcp&.thread&.alive?

    stop_service
  end
end
