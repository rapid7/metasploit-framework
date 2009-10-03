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

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	
	def initialize
		super(
			'Name'        => 'SNMP Community Scanner',
			'Version'     => '$Revision$',
			'Description' => 'Scan for SNMP devices using common community names',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
			OptPath.new('COMMUNITIES',   [ false, "The list of communities that should be attempted per host", 
					File.join(Msf::Config.install_root, "data", "wordlists", "snmp.txt")
				]
			),
			Opt::RPORT(161),
		], self.class)		
	end


	# Define our batch size
	def run_batch_size
		datastore['BATCHSIZE'].to_i
	end
	
	def configure_wordlist
		@comms = []
		File.open(datastore['COMMUNITIES'], "r") do |fd|
			buff = fd.read(fd.stat.size)
			buff.split("\n").each do |line|
				line.strip!
				next if line =~ /^#/
				next if line.empty?
				@comms << line if not @comms.include?(line)
			end
		end
	end
	
	# Operate on an entire batch of hosts at once
	def run_batch(batch)
	
		configure_wordlist if not @comms

		begin		
			udp_sock = nil
			idx = 0
			
			# Create an unbound UDP socket
			udp_sock = Rex::Socket::Udp.create()

			print_status(">> progress (#{batch[0]}-#{batch[-1]}) #{idx}/#{@comms.length * batch.length}...")	
			@comms.each do |comm|

				data = create_probe(comm)
				batch.each do |ip|

					begin
						udp_sock.sendto(data, ip, datastore['RPORT'].to_i, 0)
					rescue ::Interrupt
						raise $!
					rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
						nil
					end
				
					if (idx % 10 == 0)
						while (r = udp_sock.recvfrom(65535, 0.01) and r[1])
							parse_reply(r)
						end
					end

					if( (idx+=1) % 1000 == 0)
						print_status(">> progress (#{batch[0]}-#{batch[-1]}) #{idx}/#{@comms.length * batch.length}...")
					end					
				end
			end

			while (r = udp_sock.recvfrom(65535, 3) and r[1])
				parse_reply(r)
			end
			
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			print_status("Unknown error: #{e.class} #{e}")
		end
	end


	#
	# The response parsers
	#
	def parse_reply(pkt)

		return if not pkt[1]
		
		if(pkt[1] =~ /^::ffff:/)
			pkt[1] = pkt[1].sub(/^::ffff:/, '')
		end

		asn = ASNData.new(pkt[0])
		inf = asn.access("L0.L0.L0.L0.V1.value")
		if (inf)
			inf.gsub!(/\r|\n/, ' ')
			inf.gsub!(/\s+/, ' ')
		end

		com = asn.access("L0.V1.value")
		if(com)
			print_status("#{pkt[1]} '#{com}' '#{inf}'")

			report_auth_info(
				:host   => pkt[1],
				:proto  => 'snmp',
				:user   => 'n/a',
				:pass   => com,
				:targ_host => pkt[1],
				:targ_port => pkt[2]
			)
			
			report_service(
				:host   => pkt[1],
				:port   => pkt[2],
				:proto  => 'udp',
				:name   => 'snmp'							
			)
			
			report_note(
				:host   => pkt[1],
				:proto  => 'snmp',
				:port   => pkt[2],
				:type   => 'snmp_sysdesc',
				:data   => inf
			)
		end
	end

	def create_probe(name)
		xid = rand(0x100000000)
		pdu =	
			"\x02\x01\x01" +
			"\x04" + [name.length].pack('c') + name +
			"\xa1\x19" +
			"\x02\x04" + [xid].pack('N') +
			"\x02\x01\x00" +
			"\x02\x01\x00" +
			"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01" +
			"\x05\x00"
		head = "\x30" + [pdu.length].pack('c')
		data = head + pdu
		data
	end
	
	#
	# Parse a asn1 buffer into a hash tree
	#

	class ASNData < ::Hash

		def initialize(data)
			_parse_asn1(data, self)
		end

		def _parse_asn1(data, tree)
			x = 0
			while (data.length > 0)
				t,l = data[0,2].unpack('CC')
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



end
