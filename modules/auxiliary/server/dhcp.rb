##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex/proto/dhcp'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::DHCPServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'DHCP Server',
      'Description'    => %q{
        This module provides a DHCP service
      },
      'Author'      => [ 'scriptjunkie', 'apconole@yahoo.com' ],
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Service' ]
        ],
      'PassiveActions' =>
        [
          'Service'
        ],
      'DefaultAction'  => 'Service'
    )

    register_options(
      [
        OptString.new('SRVHOST',     [ true,  "The IP of the DHCP server" ]),
        OptString.new('NETMASK',     [ true,  "The netmask of the local subnet" ]),
        OptString.new('DHCPIPSTART', [ false,  "The first IP to give out" ]),
        OptString.new('DHCPIPEND',   [ false,  "The last IP to give out" ]),
        OptString.new('ROUTER',      [ false,  "The router IP address" ]),
        OptString.new('BROADCAST',   [ false,  "The broadcast address to send to" ]),
        OptString.new('DNSSERVER',   [ false,  "The DNS server IP address" ]),
        OptString.new('HOSTNAME',    [ false,  "The optional hostname to assign" ]),
        OptString.new('HOSTSTART',   [ false,  "The optional host integer counter" ]),
        OptString.new('FILENAME',    [ false,  "The optional filename of a tftp boot server" ])
      ], self.class)
  end

  def run
    @dhcp = Rex::Proto::DHCP::Server.new(datastore)

    print_status("Starting DHCP server...")
    @dhcp.start
    add_socket(@dhcp.sock)

    # Wait for finish..
    while @dhcp.thread.alive?
      Rex.sleep(2)
    end

    print_status("Stopping DHCP server...")
    @dhcp.stop
  end

end
