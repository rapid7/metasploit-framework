module Msf

###
#
# UdpProbeSweep
# ------------
#
# This recon module discovers hosts by sending a variety of probes to common
# services running over the UDP protocol
#
###

class Recon::Host::PortScanner::UdpProbeSweep < Msf::Recon::Discoverer::Host

	def initialize(info = {})
		super(merge_info(info,
			'Name'           => 'UDP Probe Sweeper',
			'Description'    => %q{
				This module discovers hosts by sending a variety of probes to common
			services running over the UDP protocol.
			},
			'Author'         => 'hdm',
			'Version'        => '$Revision$'
		))
		
		# Intialize the probes array
		@probes = []
		
		# Add the UDP probe method names
		@probes << 'probe_pkt_dns'
		@probes << 'probe_pkt_netbios'
		@probes << 'probe_pkt_portmap'
		@probes << 'probe_pkt_mssql'
		@probes << 'probe_pkt_snmp'		
		@probes << 'probe_pkt_sentinel'
					
	end

	# 
	# Probes each address using a variety of ports and data sets.
	#
	def probe_host(ip)

		begin		
			# No data is actually sent to this system...
			udp_sock = Rex::Socket::Udp.create(
				'PeerHost' => ip,
				'PeerPort' => 53
			)

			@probes.each do |probe|
				data, port = self.send(probe, ip)
				udp_sock.sendto(data, ip, port, 0)
			end

			alive = false

			r = udp_sock.recvfrom(65535)
			while (r[1])
				alive = true if r[1]
				r << udp_sock.recvfrom(65535)
			end

			print_status("Discovered #{ip} through a response on #{r[2]}") if alive


			alive ? HostState::Alive : HostState::Dead

		# Catch attempts to send to a broadcast address
		rescue Errno::EACCES
			HostState::Dead
		
		# Catch 'connection refused' triggered by ICMP port unreachable
		rescue Errno::ECONNREFUSED
			print_status("Discovered #{ip} through an ICMP error message")
			HostState::Alive

		# Catch any other errors...
		rescue => e
			print_status("Unknown error: #{e.to_s}")
			print_status(e.backtrace.join("\n"))
			HostState::Dead
		end
	end

	#
	# Cleans up 
	#
	def probe_host_cleanup(ip, state)

	end


	#
	# The probe definitions
	#

	def probe_pkt_dns(ip)	
		data = [rand(0xffff)].pack('n') +
		"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"+
		"\x07"+ "PROBER!"+
		"\x04"+ "TEST"+
		"\x00\x00\x10\x00\x03"
		
		return [data, 53]
	end
	
	def probe_pkt_netbios(ip)
		data = 
		"\x00\x00\x00\x00\x00\x00\x00\x00\xb3\x3f\x00\x00\x00\x01\x00\x00\x00"+
		"\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"+
		"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"+
		"\x41\x41\x00\x00\x21\x00\x01"
		return [data, 137]
	end
	
	def probe_pkt_portmap(ip)
		data =
		[
				rand(0xffffffff), # XID
				0,              # Type
				2,              # RPC Version
				100000,         # Program ID
				2,              # Program Version
				4,              # Procedure
				0, 0,   # Credentials
				0, 0,   # Verifier
		].pack('N*')
		
		return [data, 111]
	end
	
	def probe_pkt_mssql(ip)
		return ["\x02", 1434]
	end


	def probe_pkt_snmp(ip)
		data =  
			"\x30\x26" +
			"\x02\x01\x01" +
			"\x04\x06" + "public" +
			"\xa1\x19" +
			"\x02\x04" + [rand(0xffffffff)].pack('N') +
			"\x02\x01\x00" +
			"\x02\x01\x00" +
			"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01" +
			"\x05\x00"
		return [data, 161]
	end
	
	def probe_pkt_sentinel(ip)
		return ["\x7a\x00\x00\x00\x00\x00", 5093]
	end
	
end

end
