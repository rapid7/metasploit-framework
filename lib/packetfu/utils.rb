require 'singleton'
module PacketFu

	# Utils is a collection of various and sundry network utilities that are useful for packet
	# manipulation.
	class Utils
		include Singleton

		# Returns the MAC address of an IP address, or nil if it's not responsive to arp. Takes
		# a dotted-octect notation of the target IP address, as well as a number of parameters:
		#
		# === Parameters
		#   :eth_saddr
		#    Source MAC address. Defaults to "00:00:00:00:00:00".
		#   :ip_saddr
		#    Source IP address. Defaults to "0.0.0.0"
		#   :flavor
		#    The flavor of the ARP request. Defaults to :none.
		#   :timeout
		#    Timeout in seconds. Defaults to 3.
		#
		#  === Example
		#    PacketFu::Utils::arp("192.168.1.1") #=> "00:18:39:01:33:70"
		#    PacketFu::Utils::arp("192.168.1.1", :timeout => 5, :flavor => :hp_deskjet)
		#  
		#  === Warning
		#  
		#  It goes without saying, spewing forged ARP packets on your network is a great way to really
		#  irritate your co-workers.
		def self.arp(target_ip,args={})
			arp_pkt = PacketFu::ARPPacket.new(:flavor => (args[:flavor] || :none))
			arp_pkt.eth_saddr = arp_pkt.arp_saddr_mac = (args[:eth_saddr] || ($packetfu_default.config[:eth_saddr] if $packetfu_default) || "00:00:00:00:00:00" )
			arp_pkt.eth_daddr = "ff:ff:ff:ff:ff:ff"
			arp_pkt.arp_daddr_mac = "00:00:00:00:00:00"
			arp_pkt.arp_saddr_ip = (args[:ip_saddr] || ($packetfu_default.config[:ip_saddr] if $packetfu_default) || "0.0.0.0")
			arp_pkt.arp_daddr_ip = target_ip 
			iface = (args[:iface] || ($packetfu_default.iface if $packetfu_default) || "eth0")
			# Stick the Capture object in its own thread.
			cap_thread = Thread.new do
				target_mac = nil
				cap = PacketFu::Capture.new(:iface => iface, :start => true, 
				:filter => "arp src #{target_ip} and ether dst #{arp_pkt.eth_saddr}")
				arp_pkt.to_w(iface) # Shorthand for sending single packets to the default interface.
				timeout = 0
				while target_mac.nil? && timeout <= (args[:timeout] || 3)
					if cap.save > 0
						arp_response = PacketFu::Packet.parse(cap.array[0])
						target_mac = arp_response.arp_saddr_mac if arp_response.arp_saddr_ip = target_ip
					end
					timeout += 0.1
					sleep 0.1 # Check for a response ten times per second.
				end
				target_mac
			end # cap_thread
			cap_thread.value
		end # def self.arp

		# Discovers the local IP and Ethernet address, which is useful for writing
		# packets you expect to get a response to. Note, this is a noisy
		# operation; a UDP packet is generated and dropped on to the default (or named)
		# interface, and then captured (which means you need to be root to do this).
		#
		# whoami? returns a hash of :eth_saddr, :eth_src, :ip_saddr, :ip_src,
		# :eth_dst, and :eth_daddr (the last two are usually suitable for a
		# gateway mac address). It's most useful as an argument to PacketFu::Config.new.
		#
		# === Parameters
		#   :iface => "eth0"
		#    An interface to listen for packets on. Note that since we rely on the OS to send the probe packet,
		#    you will need to specify a target which will use this interface.
		#   :target => "1.2.3.4"
		#    A target IP address. By default, a packet will be sent to a random address in the 177/8 network.
		#    Since this network is IANA reserved (for now), this network should be handled by your default gateway
		#    and default interface.
		def self.whoami?(args={})
			if args[:iface] =~ /^lo/ # Linux loopback more or less. Need a switch for windows loopback, too.
				dst_host = "127.0.0.1"
			else
				dst_host = (args[:target] || IPAddr.new((rand(16777216) + 2969567232), Socket::AF_INET).to_s)
			end

			dst_port = rand(0xffff-1024)+1024
			msg = "PacketFu whoami? packet #{(Time.now.to_i + rand(0xffffff)+1)}"
			cap = Capture.new(:iface => (args[:iface] || Pcap.lookupdev), :start => true, :filter => "udp and dst host #{dst_host} and dst port #{dst_port}")
			UDPSocket.open.send(msg,0,dst_host,dst_port)
			cap.save
			pkt = Packet.parse(cap.array[0]) unless cap.save.zero?
			timeout = 0
			while timeout < 1 # Sometimes packet generation can be a little pokey.
				if pkt
					timeout = 1.1 # Cancel the timeout
					if pkt.payload == msg
					my_data =	{
						:iface => args[:iface] || Pcap.lookupdev || 'lo',
						:pcapfile => args[:pcapfile] || "/tmp/out.pcap",
						:eth_saddr => pkt.eth_saddr,
						:eth_src => pkt.eth_src.to_s,
						:ip_saddr => pkt.ip_saddr,
						:ip_src => pkt.ip_src.to_s,
						:eth_dst => pkt.eth_dst.to_s,
						:eth_daddr => pkt.eth_daddr
					}
					else raise SecurityError, 
						"whoami() packet doesn't match sent data. Something fishy's going on."
					end
				else
					sleep 0.1; timeout += 0.1
					cap.save
					pkt = Packet.parse(cap.array[0]) unless cap.save.zero?
				end
				raise SocketError, "Didn't recieve the whomi() packet." if !pkt
				cap = nil
			end
			my_data
		end

		# This is a brute-force approach at trying to find a suitable interface with an IP address.
		def self.lookupdev
			# XXX cycle through eth0-9 and wlan0-9, and if a cap start throws a RuntimeErorr (and we're
			# root), it's not a good interface. Boy, really ought to fix lookupdev directly with another
			# method that returns an array rather than just the first candidate.
		end


	end # class Utils

end # module PacketFu