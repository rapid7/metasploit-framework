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

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Capture
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'ARP Sweep Local Network Discovery',
			'Version'     => '$Revision$',
			'Description' => %q{
				Enumerate alive Hosts in local network using ARP requests.
			},
			'Author'      => 'belch',
			'License'     => MSF_LICENSE
		)

		register_options([
			OptString.new('SHOST', [false, "Source IP Address"]),
			OptString.new('SMAC', [false, "Source MAC Address"]),
			# one re-register TIMEOUT here with a lower value, cause 5 seconds will be enough in most of the case
			OptInt.new('TIMEOUT', [true, 'The number of seconds to wait for new data', 5]),
		], self.class)

		deregister_options('SNAPLEN', 'FILTER', 'PCAPFILE', 'UDP_SECRET', 'GATEWAY', 'NETMASK')
	end

	def run_batch_size
		datastore['BATCHSIZE'] || 256
	end

	def run_batch(hosts)

		@netifaces = true
		if not netifaces_implemented? 
			print_error("WARNING : Pcaprub is not uptodate, some functionality will not be available")
			@netifaces = false
		end

		# XXX: This needs to be more automatic /and/ not rely on Pcap.interfaces, since
		# it's never going to be reliable anyway.
		shost = datastore['SHOST']
		shost ||= get_ipv4_addr(datastore['INTERFACE']) if @netifaces
		raise RuntimeError ,'SHOST should be defined' unless shost
		
		smac  = datastore['SMAC']
		smac ||= get_mac(datastore['INTERFACE']) if @netifaces
		raise RuntimeError ,'SMAC should be defined' unless smac

		open_pcap({'SNAPLEN' => 68, 'FILTER' => "arp[6:2] == 0x0002"})

		begin

		hosts.each do |dhost|
			if dhost != shost
				probe = buildprobe(shost, smac, dhost)
				capture.inject(probe)

				while(reply = getreply())
					next if not reply[:arp]
					print_status("#{reply[:arp].spa} appears to be up.")

					report_host(:host => reply[:arp].spa, :mac=>reply[:arp].sha)
				end
			end
		end

		etime = Time.now.to_f + datastore['TIMEOUT']
		while (Time.now.to_f < etime)
			while(reply = getreply())
				next if not reply[:arp]
				print_status("#{reply[:arp].spa} appears to be up.")

				report_host(:host => reply[:arp].spa, :mac=>reply[:arp].sha)
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
end
