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
			pkt_bytes = capture.next()
			Kernel.select(nil,nil,nil,0.1)
			next if not pkt_bytes
			p = PacketFu::Packet.parse(pkt_bytes)
			# Don't bother checking if it's an echo reply, since Neighbor Solicitations
			# and any other response is just as good.
			next unless p.is_ipv6? 
			host_addr = p.ipv6_saddr
			host_mac = p.eth_saddr
			next if host_mac == smac
			unless hosts[host_addr] == host_mac
				hosts[host_addr] = host_mac
				print_status("   |*| #{host_addr} => #{host_mac}")
			end
		end
		return hosts
	end

	def smac
		datastore['SMAC'].to_s.empty? ? ipv6_mac : datastore['SMAC']
	end

	def run
		# Start capture
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
