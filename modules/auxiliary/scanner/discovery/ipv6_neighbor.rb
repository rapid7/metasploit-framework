##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framwork/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Capture
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner


	def initialize
		super(
			'Name'        => 'IPv6 Local Neighbor Discovery',
			'Version'     => '$Revision$',
			'Description' => %q{
				Enumerate local IPv6 hosts which respond to Neighbor Solicitations with a link-local address.
				Note, that like ARP scanning, this usually cannot be performed beyond the local
				broadcast network.
		},
		'Author'      => 'belch',
		'License'     => MSF_LICENSE
		)

		register_options(
			[
				OptString.new('SHOST', [true, "Source IP Address"]),
				OptString.new('SMAC', [true, "Source MAC Address"]),
		], self.class)

		deregister_options('SNAPLEN', 'FILTER')
	end

	def run_batch_size
		datastore['BATCHSIZE'] || 256
	end

	def run_batch(hosts)
		print_status("IPv4 Hosts Discovery")

		shost = datastore['SHOST']
		smac  = datastore['SMAC']

		addrs = []

		open_pcap({'SNAPLEN' => 68, 'FILTER' => "arp[6:2] == 0x0002"})

		begin
			hosts.each do |dhost|

				probe = buildprobe(datastore['SHOST'], datastore['SMAC'], dhost)
				capture.inject(probe)

				while(reply = getreply())
					next if not reply[:arp]
					print_status("#{reply[:arp].spa} is alive.")

					addrs << [reply[:arp].spa, reply[:arp].sha]
					report_host(:host => reply[:arp].spa, :mac=>reply[:arp].sha)
				end
			end

			etime = Time.now.to_f + (hosts.length * 0.05)

			while (Time.now.to_f < etime)
				while(reply = getreply())
					next if not reply[:arp]
					print_status("#{reply[:arp].spa} is alive.")

					addrs << [reply[:arp].spa, reply[:arp].sha]
				end

				Kernel.select(nil, nil, nil, 0.50)
			end

		ensure
			close_pcap()
		end

		neighbor_discovery(addrs)
	end


	def map_neighbor(nodes, adv)
		nodes.each do |node|
			ipv4_addr, mac_addr = node
			next if not adv[:eth].src_mac.eql? mac_addr

			ipv6_addr = Racket::L3::Misc.long2ipv6(adv[:ipv6].src_ip)
			return {:eth => mac_addr, :ipv4 => ipv4_addr, :ipv6 => ipv6_addr}

		end

		nil
	end


	def neighbor_discovery(neighs)
		print_status("IPv6 Neighbor Discovery")

		smac  = datastore['SMAC']
		open_pcap({'SNAPLEN' => 68, 'FILTER' => "icmp6"})

		begin
			neighs.each do |neigh|
				host, dmac = neigh

				shost = Racket::L3::Misc.linklocaladdr(smac)
				neigh = Racket::L3::Misc.linklocaladdr(dmac)

				probe = buildsolicitation(smac, shost, neigh)

				capture.inject(probe)

				while(adv = getadvertisement())
					next if not adv[:icmpv6]

					addr = map_neighbor(neighs, adv)
					next if not addr

					print_status("#{addr[:ipv4]} maps to IPv6 link local address #{addr[:ipv6]}")
				end
			end

			etime = Time.now.to_f + (neighs.length * 0.5)

			while (Time.now.to_f < etime)
				while(adv = getadvertisement())
					next if not adv[:icmpv6]

					addr = map_neighbor(neighs, adv)
					next if not addr

					print_status("#{addr[:ipv4]} maps to IPv6 link local address #{addr[:ipv6]}")
				end
				Kernel.select(nil, nil, nil, 0.50)
			end

		ensure
			close_pcap()
		end
	end

	def buildprobe(shost, smac, dhost)
		n = Racket::Racket.new
		n.l2 = Racket::L2::Ethernet.new(Racket::Misc.randstring(14))
		n.l2.src_mac = smac
		n.l2.dst_mac = 'ff:ff:ff:ff:ff:ff'
		n.l2.ethertype = 0x0806

		n.l3 = Racket::L3::ARP.new
		n.l3.opcode = Racket::L3::ARP::ARPOP_REQUEST
		n.l3.sha = n.l2.src_mac
		n.l3.tha = n.l2.dst_mac
		n.l3.spa = shost
		n.l3.tpa = dhost
		n.pack
	end

	def getreply
		pkt = capture.next
		return if not pkt

		eth = Racket::L2::Ethernet.new(pkt)
		return if not eth.ethertype == 0x0806

		arp = Racket::L3::ARP.new(eth.payload)
		return if not arp.opcode == Racket::L3::ARP::ARPOP_REPLY

		{:raw => pkt, :eth => eth, :arp => arp}
	end

	def buildsolicitation(smac, shost, neigh)
		dmac  = Racket::L3::Misc.soll_mcast_mac(neigh)
		dhost = Racket::L3::Misc.soll_mcast_addr6(neigh)

		n = Racket::Racket.new
		n.l2 = Racket::L2::Ethernet.new(Racket::Misc.randstring(14))
		n.l2.src_mac = smac
		n.l2.dst_mac = dmac
		n.l2.ethertype = 0x86dd

		n.l3 = Racket::L3::IPv6.new
		n.l3.src_ip = Racket::L3::Misc.ipv62long(shost)
		n.l3.dst_ip = Racket::L3::Misc.ipv62long(dhost)
		n.l3.nhead  = 0x3a
		n.l3.ttl    = 0xff


		n.l4 = Racket::L4::ICMPv6NeighborSolicitation.new
		n.l4.address = Racket::L3::Misc.ipv62long(neigh)
		n.l4.slla = smac

		n.l4.fix!(n.l3.src_ip, n.l3.dst_ip)
		n.pack
	end

	def getadvertisement
		pkt = capture.next
		return if not pkt

		eth = Racket::L2::Ethernet.new(pkt)
		return if not eth.ethertype == 0x86dd

		ipv6 = Racket::L3::IPv6.new(eth.payload)
		return if not ipv6.nhead == 0x3a

		icmpv6 = Racket::L4::ICMPv6.new(ipv6.payload)
		return if not icmpv6.type == Racket::L4::ICMPv6::ICMPv6_TYPE_NEIGHBOR_ADVERTISEMENT

		icmpv6 = Racket::L4::ICMPv6NeighborAdvertisement.new(ipv6.payload)
		{:raw => pkt, :eth => eth, :ipv6 => ipv6, :icmpv6 => icmpv6}
	end
end
