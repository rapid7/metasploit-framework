# -*- coding: binary -*-


module Msf

###
#
# This mixin provides a DHCPServer
#
###
module Exploit::DHCPServer
  include ::Msf::Exploit::Remote::SocketServer

  def initialize(info = {})
    super(update_info(info,
      'Stance' => Msf::Exploit::Stance::Passive,
    ))

    register_options(
      [
        OptString.new('DHCPINTERFACE',[ false, "The network interface to use for broadcast" ]),
        OptAddress.new('SRVHOST',     [ true,  "The IP of the DHCP server" ]),
        OptAddress.new('NETMASK',     [ true,  "The netmask of the local subnet" ]),
        OptAddress.new('DHCPIPSTART', [ false, "The first IP to give out" ]),
        OptAddress.new('DHCPIPEND',   [ false, "The last IP to give out" ]),
        OptAddress.new('ROUTER',      [ false, "The router IP address" ]),
        OptAddress.new('BROADCAST',   [ false, "The broadcast address to send to" ]),
        OptAddress.new('DNSSERVER',   [ false, "The DNS server IP address" ]),
        OptString.new('DOMAINNAME',  [ false, "The optional domain name to assign" ]),
        OptString.new('HOSTNAME',    [ false, "The optional hostname to assign" ]),
        OptString.new('HOSTSTART',   [ false, "The optional host integer counter" ]),
        OptString.new('FILENAME',    [ false, "The optional filename of a tftp boot server" ])
      ], self.class)

    @dhcp = nil
  end

  def start_service(hash = {}, context = {})
    @dhcp = Rex::Proto::DHCP::Server.new(hash, context)
    vprint_status("Starting DHCP server")
    @dhcp.start
    add_socket(@dhcp.sock)
    @dhcp
  end

  def stop_service
    vprint_status("Stopping DHCP server")
    @dhcp.stop
  end

  def validate
     unless _determine_server_comm(datastore['SRVHOST']) == Rex::Socket::Comm::Local
       raise Msf::OptionValidateError.new({ 'SRVHOST' => 'SRVHOST can not be forwarded via a session.' })
     end
  end

  attr_accessor :dhcp
end

end
