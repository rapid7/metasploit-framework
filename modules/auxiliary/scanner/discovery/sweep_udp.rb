require 'msf/core'

module Msf

class Auxiliary::Scanner::Discovery::SweepUDP < Msf::Auxiliary

	include Auxiliary::Report
	include Auxiliary::Scanner
	
	def initialize
		super(
			'Name'        => 'UDP Service Sweeper',
			'Version'     => '$Revision: 3624 $',
			'Description' => 'Detect common UDP services',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
		], self.class)

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


	# Define our batch size
	def run_batch_size
		datastore['BATCHSIZE'].to_i
	end
	
	# Fingerprint a single host
	def run_batch(batch)
	
		print_status("Sending #{@probes.length.to_s} probes to #{batch[0]}->#{batch[-1]} (#{batch.length.to_s} hosts)")

		begin		
			udp_sock = nil
			idx = 0
			
			# Create an unbound UDP socket
			udp_sock = Rex::Socket::Udp.create()
	
			# Send each probe to each host
			@probes.each do |probe|
			batch.each   do |ip|
				begin
					data, port = self.send(probe, ip)
					udp_sock.sendto(data, ip, port, 0)
				rescue ::Errno::EACCES,Errno::EHOSTUNREACH
				end
				
				if (idx % 30 == 0)
					while (r = udp_sock.recvfrom(65535, 0.1) and r[1])
						parse_reply(r)
					end
				end
				
				idx += 1
			end
			end

			while (r = udp_sock.recvfrom(65535, 3) and r[1])
				parse_reply(r)
			end
			
		rescue => e
			print_status("Unknown error: #{e.to_s}")
			print_status(e.backtrace.join("\n"))
		end
	end


	#
	# The response parsers
	#
	def parse_reply(pkt)
		@results ||= {}
		
		# Ignore "empty" packets
		return if not pkt[1]
		
		# Ignore duplicates
		hkey = "#{pkt[1]}:#{pkt[2].to_s}"
		return if @results[hkey]
		
		app = 'unknown'
		inf = ''
		
		case pkt[2]
			when 53
				app = 'DNS'
			when 137
				app = 'NetBIOS'
			when 111
				app = 'Portmap'
			when 1434
				app = 'SQL Server'
				idx = pkt[0].index('ServerName')
				inf = pkt[0][idx, pkt[0].length-idx] if idx
			when 161
				app = 'SNMP'
			when 5093
				app = 'Sentinel'
		end
		
		print_status("Discovered #{app} on #{pkt[1]} (#{inf})")
		
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
		[rand(0xffff)].pack('n')+
		"\x00\x00\x00\x01\x00\x00\x00\x00"+
		"\x00\x00\x20\x43\x4b\x41\x41\x41"+
		"\x41\x41\x41\x41\x41\x41\x41\x41"+
		"\x41\x41\x41\x41\x41\x41\x41\x41"+
		"\x41\x41\x41\x41\x41\x41\x41\x41"+
		"\x41\x41\x41\x00\x00\x21\x00\x01"	

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
