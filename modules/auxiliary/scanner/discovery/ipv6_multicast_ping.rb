##
# $Id$
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Capture
	include Msf::Exploit::Remote::Ipv6
	include Msf::Auxiliary::Report

	def initialize
		super(
		'Name'        => 'IPv6 Link Local/Node Local Ping Discovery',
		'Version'     => '$Revision$',
		'Description' => %q{
				Send a ICMPv6 ping request to all default multicast addresses, and wait to see who responds.
		},
		'Author'      => 'wuntee',
		'License'     => MSF_LICENSE,
		'References'    =>
			[
				['URL','http://wuntee.blogspot.com/2010/12/ipv6-ping-host-discovery-metasploit.html']
			]
		)

		deregister_options('SNAPLEN', 'FILTER', 'RHOST', 'PCAPFILE')
	end

	def listen_for_ping_response(opts = {})
		hosts = {}
		timeout = opts['TIMEOUT'] || datastore['TIMEOUT']
		prefix = opts['PREFIX'] || datastore['PREFIX']

		max_epoch = ::Time.now.to_i + timeout

		while(::Time.now.to_i < max_epoch)
			pkt = capture.next()
			Kernel.select(nil,nil,nil,0.1)
			next if not pkt
			eth = Racket::L2::Ethernet.new(pkt)

			next if not eth.ethertype.eql?(Racket::L2::Ethernet::ETHERTYPE_IPV6)
			ipv6 = Racket::L3::IPv6.new(eth.payload)

			next if not ipv6.nhead == 0x3a
			icmpv6 = Racket::L4::ICMPv6.new(ipv6.payload)

			next if not icmpv6.type == Racket::L4::ICMPv6Generic::ICMPv6_TYPE_ECHO_REPLY

			icmpv6 = Racket::L4::ICMPv6EchoReply.new(ipv6.payload)
			host_addr = Racket::L3::Misc.long2ipv6(ipv6.src_ip)
			host_mac = eth.src_mac

			if(!hosts[host_addr].eql?(host_mac))
				hosts[host_addr] = host_mac
				print_status("   |*| #{host_addr} => #{host_mac}")
				# report_host(:mac => host_mac, :host => host_addr)
			end
		end
		return(hosts)
	end

	def run
		# Start caputre
		open_pcap({'FILTER' => "icmp6"})

		# Send ping
		print_status("Sending multicast pings...")
		dmac = "33:33:00:00:00:01"
		
		# Figure out our source address by the link-local interface
		shost = ipv6_link_address
		
		ping6("FF01::1", {"DMAC" => dmac, "SHOST" => shost, "WAIT" => false})
		ping6("FF01::2", {"DMAC" => dmac, "SHOST" => shost, "WAIT" => false})
		ping6("FF02::1", {"DMAC" => dmac, "SHOST" => shost, "WAIT" => false})
		ping6("FF02::2", {"DMAC" => dmac, "SHOST" => shost, "WAIT" => false})

		# Listen for host advertisments
		print_status("Listening for responses...")
		listen_for_ping_response()

		# Close capture
		close_pcap()
	end

end
