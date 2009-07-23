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
			OptString.new('SHOST', [true, "Source IP Address"]),
			OptString.new('SMAC', [true, "Source MAC Address"]),
		], self.class)
		
	end

	def run_batch_size
		datastore['BATCHSIZE'] || 256
	end

	def run_batch(hosts)
		
		shost = datastore['SHOST'] 
		smac  = datastore['SMAC']
		
		open_pcap({'SNAPLEN' => 68, 'FILTER' => "arp[6:2] == 0x0002"})	

		begin
		
		hosts.each do |dhost|
			probe = buildprobe(datastore['SHOST'], datastore['SMAC'], dhost)
			capture.inject(probe)

			while(reply = getreply())
				next if not reply[:arp]
				print_status("#{reply[:arp].spa} appears to be up.")
				
				report_host(:host => reply[:arp].spa, :mac=>reply[:arp].sha)
			end
		end
		
		etime = Time.now.to_f + (hosts.length * 0.05)
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
		n.l2 = Racket::Ethernet.new(Racket::Misc.randstring(14))
		n.l2.src_mac = smac
		n.l2.dst_mac = 'ff:ff:ff:ff:ff:ff'
		n.l2.ethertype = 0x0806
		
		n.l3 = Racket::ARP.new
		n.l3.opcode = Racket::ARP::ARPOP_REQUEST
		n.l3.sha = n.l2.src_mac
		n.l3.tha = n.l2.dst_mac
		n.l3.spa = shost
		n.l3.tpa = dhost
		n.pack
	end
	
	def getreply
		pkt = capture.next
		return if not pkt
		
		eth = Racket::Ethernet.new(pkt)
		return if not eth.ethertype == 0x0806

		arp = Racket::ARP.new(eth.payload)
		return if not arp.opcode == Racket::ARP::ARPOP_REPLY

		{:raw => pkt, :eth => eth, :arp => arp}
	end
end
