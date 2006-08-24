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
				ver = nil
				
				if (not ver and pkt[0] =~ /([6789]\.[\w\.\-_\:\(\)\[\]\/\=\+\|\{\}]+)/i)
					ver = 'BIND ' + $1
				end

				ver = 'Microsoft' if (not ver and pkt[0][2,4] == "\x81\x04\x00\x01")
				ver = 'TinyDNS'   if (not ver and pkt[0][2,4] == "\x81\x81\x00\x01")
				
				ver = pkt[0].unpack('H*')[0] if not ver
				inf = ver if ver
			when 137
				app = 'NetBIOS'
				# inf = pkt[0].unpack('H*')[0]
			when 111
				app = 'Portmap'
				# inf = pkt[0].unpack('H*')[0]
			when 1434
				app = 'SQL Server'
				mssql_ping_parse(pkt[0]).each_pair { |k,v|
					inf += k+'='+v+' '
				}
				
			when 161
				app = 'SNMP'
				begin
					asn = ASNData.new(pkt[0])
					inf = asn.access("L0.L0.L0.L0.V1.value")
					if (inf)
						inf.gsub!(/\r|\n/, ' ')
						inf.gsub!(/\s+/, ' ')
					end
				rescue ::Exception
				end
			when 5093
				app = 'Sentinel'
		end
		
		print_status("Discovered #{app} on #{pkt[1]} (#{inf})")
		
	end

	#
	# Parse a asn1 buffer into a hash tree
	#

	class ASNData < Hash

		def initialize(data)
			_parse_asn1(data, self)
		end

		def _parse_asn1(data, tree)
			x = 0
			while (data.length > 0)
				t = data[0]
				l = data[1]
				i = 2

				if (l > 0x7f)
					lb = l - 0x80
					l = (("\x00" * (4-lb)) + data[i, lb]).unpack('N')[0]
					i += lb
				end

				buff = data[i, l]

				tree[:v] ||= []
				tree[:l] ||= []
				case t
					when 0x00...0x29
						tree[:v] << [t, buff]
					else
						tree[:l][x] ||= ASNData.new(buff)
						x += 1
				end
				data = data[i + l, data.length - l]
			end		
		end

		def access(desc)
			path = desc.split('.')
			node = self
			path.each_index do |i|
				case path[i]
					when /^V(\d+)$/
						if (node[:v] and node[:v][$1.to_i])
							node = node[:v][$1.to_i]
							next
						else
							return nil
						end
					when /^L(\d+)$/
						if (node[:l] and node[:l][$1.to_i])
							node = node[:l][$1.to_i]
							next
						else
							return nil
						end		
					when 'type'
						return (node and node[0]) ? node[0] : nil
					when 'value'
						return (node and node[1]) ? node[1] : nil
					else
						return nil
				end
			end
			return node
		end
	end

	#
	# Parse a 'ping' response and format as a hash
	#
	def mssql_ping_parse(data)
		res = {}
		var = nil
		idx = data.index('ServerName')
		return res if not idx
		
		data[idx, data.length-idx].split(';').each do |d|
			if (not var)
				var = d
			else
				if (var.length > 0)
					res[var] = d
					var = nil
				end
			end
		end
		
		return res
	end
	
	#
	# The probe definitions
	#

	def probe_pkt_dns(ip)	
		data = [rand(0xffff)].pack('n') +
		"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"+
		"\x07"+ "VERSION"+
		"\x04"+ "BIND"+
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
