# -*- coding: binary -*-
require 'singleton'
module PacketFu

	# Utils is a collection of various and sundry network utilities that are useful for packet
	# manipulation.
	class Utils

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
			iface = args[:iface] || :eth0
			args[:config] ||= whoami?(:iface => iface)
			arp_pkt = PacketFu::ARPPacket.new(:flavor => (args[:flavor] || :none), :config => args[:config])
			arp_pkt.eth_daddr = "ff:ff:ff:ff:ff:ff"
			arp_pkt.arp_daddr_mac = "00:00:00:00:00:00"
			arp_pkt.arp_daddr_ip = target_ip
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
		end

		# Discovers the local IP and Ethernet address, which is useful for writing
		# packets you expect to get a response to. Note, this is a noisy
		# operation; a UDP packet is generated and dropped on to the default (or named)
		# interface, and then captured (which means you need to be root to do this).
		#
		# whoami? returns a hash of :eth_saddr, :eth_src, :ip_saddr, :ip_src, 
		# :ip_src_bin, :eth_dst, and :eth_daddr (the last two are usually suitable 
		# for a gateway mac address). It's most useful as an argument to 
		# PacketFu::Config.new, or as an argument to the many Packet constructors.
		#
		# Note that if you have multiple interfaces with the same route (such as when
		# wlan0 and eth0 are associated to the same network), the "first" one
		# according to Pcap.lookupdev will be used, regardless of which :iface you 
		# pick.
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
			unless args.kind_of? Hash
				raise ArgumentError, "Argument to `whoami?' must be a Hash"
			end
			if args[:iface].to_s =~ /^lo/ # Linux loopback more or less. Need a switch for windows loopback, too.
				dst_host = "127.0.0.1"
			else
				dst_host = (args[:target] || IPAddr.new((rand(16777216) + 2969567232), Socket::AF_INET).to_s)
			end

			dst_port = rand(0xffff-1024)+1024
			msg = "PacketFu whoami? packet #{(Time.now.to_i + rand(0xffffff)+1)}"
			iface = (args[:iface] || ENV['IFACE'] || Pcap.lookupdev || :lo ).to_s
			cap = PacketFu::Capture.new(:iface => iface, :promisc => false, :start => true, :filter => "udp and dst host #{dst_host} and dst port #{dst_port}")
			udp_sock = UDPSocket.new
			udp_sock.send(msg,0,dst_host,dst_port)
			udp_sock = nil
			cap.save
			pkt = Packet.parse(cap.array[0]) unless cap.save.zero?
			timeout = 0
			while timeout < 1 # Sometimes packet generation can be a little pokey.
				if pkt
					timeout = 1.1 # Cancel the timeout
					if pkt.payload == msg
					my_data =	{
						:iface => (args[:iface] || ENV['IFACE'] || Pcap.lookupdev || "lo").to_s,
						:pcapfile => args[:pcapfile] || "/tmp/out.pcap",
						:eth_saddr => pkt.eth_saddr,
						:eth_src => pkt.eth_src.to_s,
						:ip_saddr => pkt.ip_saddr,
						:ip_src => pkt.ip_src,
						:ip_src_bin => [pkt.ip_src].pack("N"),
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
				raise SocketError, "Didn't receive the whomi() packet, can't automatically configure." if !pkt
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

		# Handles ifconfig for various (okay, two) platforms.
		# Will have Windows done shortly.
		#
		# Takes an argument (either string or symbol) of the interface to look up, and 
		# returns a hash which contains at least the :iface element, and if configured, 
		# these additional elements:
		#
		#   :eth_saddr  # A human readable MAC address
		#   :eth_src    # A packed MAC address
		#   :ip_saddr   # A dotted-quad string IPv4 address
		#   :ip_src     # A packed IPv4 address
		#   :ip4_obj    # An IPAddr object with bitmask
		#   :ip6_saddr  # A colon-delimited hex IPv6 address, with bitmask
		#   :ip6_obj    # An IPAddr object with bitmask
		#
		# === Example
		#   PacketFu::Utils.ifconfig :wlan0 # Not associated yet
		#   #=> {:eth_saddr=>"00:1d:e0:73:9d:ff", :eth_src=>"\000\035\340s\235\377", :iface=>"wlan0"}
		#   PacketFu::Utils.ifconfig("eth0") # Takes 'eth0' as default
		#   #=> {:eth_saddr=>"00:1c:23:35:70:3b", :eth_src=>"\000\034#5p;", :ip_saddr=>"10.10.10.9", :ip4_obj=>#<IPAddr: IPv4:10.10.10.0/255.255.254.0>, :ip_src=>"\n\n\n\t", :iface=>"eth0", :ip6_saddr=>"fe80::21c:23ff:fe35:703b/64", :ip6_obj=>#<IPAddr: IPv6:fe80:0000:0000:0000:0000:0000:0000:0000/ffff:ffff:ffff:ffff:0000:0000:0000:0000>}  
		#   PacketFu::Utils.ifconfig :lo
		#   #=> {:ip_saddr=>"127.0.0.1", :ip4_obj=>#<IPAddr: IPv4:127.0.0.0/255.0.0.0>, :ip_src=>"\177\000\000\001", :iface=>"lo", :ip6_saddr=>"::1/128", :ip6_obj=>#<IPAddr: IPv6:0000:0000:0000:0000:0000:0000:0000:0001/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff>}
		def self.ifconfig(iface='eth0')
			ret = {}
			iface = iface.to_s.scan(/[0-9A-Za-z]/).join # Sanitizing input, no spaces, semicolons, etc.
			case RUBY_PLATFORM
			when /linux/i
				ifconfig_data = %x[ifconfig #{iface}]
				if ifconfig_data =~ /#{iface}/i
					ifconfig_data = ifconfig_data.split(/[\s]*\n[\s]*/)
				else
					raise ArgumentError, "Cannot ifconfig #{iface}"
				end
				real_iface = ifconfig_data.first
				ret[:iface] = real_iface.split.first.downcase
				if real_iface =~ /[\s]HWaddr[\s]+([0-9a-fA-F:]{17})/i
					ret[:eth_saddr] = $1.downcase
					ret[:eth_src] = EthHeader.mac2str(ret[:eth_saddr])
				end
				ifconfig_data.each do |s|
					case s
					when /inet addr:[\s]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(.*Mask:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+))?/i
						ret[:ip_saddr] = $1
						ret[:ip_src] = [IPAddr.new($1).to_i].pack("N")
						ret[:ip4_obj] = IPAddr.new($1)
						ret[:ip4_obj] = ret[:ip4_obj].mask($3) if $3
					when /inet6 addr:[\s]*([0-9a-fA-F:\x2f]+)/
						ret[:ip6_saddr] = $1
						ret[:ip6_obj] = IPAddr.new($1)
					end
				end # linux
			when /darwin/i
				ifconfig_data = %x[ifconfig #{iface}]
				if ifconfig_data =~ /#{iface}/i
					ifconfig_data = ifconfig_data.split(/[\s]*\n[\s]*/)
				else
					raise ArgumentError, "Cannot ifconfig #{iface}"
				end
				real_iface = ifconfig_data.first
				ret[:iface] = real_iface.split(':')[0]
				ifconfig_data.each do |s|
					case s
					when /ether[\s]([0-9a-fA-F:]{17})/i
						ret[:eth_saddr] = $1
						ret[:eth_src] = EthHeader.mac2str(ret[:eth_saddr])
					when /inet[\s]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(.*Mask:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+))?/i
						ret[:ip_saddr] = $1
						ret[:ip_src] = [IPAddr.new($1).to_i].pack("N")
						ret[:ip4_obj] = IPAddr.new($1)
						ret[:ip4_obj] = ret[:ip4_obj].mask($3) if $3
					when /inet6[\s]*([0-9a-fA-F:\x2f]+)/
						ret[:ip6_saddr] = $1
						ret[:ip6_obj] = IPAddr.new($1)
					end
				end # darwin
			end # RUBY_PLATFORM
			ret
		end

	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
