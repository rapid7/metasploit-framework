##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	
	def initialize
		super(
			'Name'        => 'SNMP Scanner',
			'Version'     => '0.1',
			'Description' => 'Probe for SNMP services with a given community string',
			'Author'      => 'tebo <tebo [at] attackresearch [dot] com>',
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			OptString.new('COMMUNITY', [true, 'The community string to scan with', 'public']),
		], self.class)

	end
	
	def run_host(ip)
	
		begin		

			udp_sock = Rex::Socket::Udp.create()
			name = datastore['COMMUNITY']
			pdu =	"\x02\x01\x01" +
				"\x04" + [name.length].pack('c') + name +
				"\xa1\x19" +
				"\x02\x04" + [rand(0xffffffff)].pack('N') +
				"\x02\x01\x00" +
				"\x02\x01\x00" +
				"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01" +
				"\x05\x00"
			head = "\x30" + [pdu.length].pack('c')
			data = head + pdu
	
			begin
				udp_sock.sendto(data, ip, 161, 0)
			rescue ::Interrupt
					raise $!
			rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
					nil
			end

			while (r = udp_sock.recvfrom(65535, 3) and r[1])
				ans = parse_reply(r)
			end
			
			if not ans.nil?
				print_status("Discovered #{datastore['COMMUNITY']} on #{ip} (#{ans})")
				report_auth_info(
					:host   => ip,
					:proto  => 'snmp',
					:user   => 'n/a',
					:pass   => datastore['COMMUNITY'],
					:targ_host      => ip,
					:targ_port      => 161
	                        )
        		end
			
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			print_status("Unknown error: #{e.class} #{e}")
		end
	end


	def parse_reply(pkt)

		begin
			asn = ASNData.new(pkt[0])
			inf = asn.access("L0.L0.L0.L0.V1.value")
			if (inf)
				inf.gsub!(/\r|\n/, ' ')
				inf.gsub!(/\s+/, ' ')
			
			end
		rescue ::Exception
		end
		return inf
	end

	#
	# Parse a asn1 buffer into a hash tree
	#
	# Thanks to hdm for his ASN-fu untouched in all it's glory
	class ASNData < ::Hash

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
		
end

