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
			'Name'        => 'SIP username enumerator',
			'Version'     => '$Revision: 6435 $',
			'Description' => 'Scan for numeric username/extensions using OPTIONS/REGISTER requests',
			'Author'      => 'et',
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
			OptInt.new('MINEXT',   [true, 'Starting extension',0]),
			OptInt.new('MAXEXT',   [true, 'Ending extension', 9999]),
			OptInt.new('PADLEN',   [true, 'Cero padding maximum length', 4]),
			OptString.new('METHOD', [true, 'Enumeration method to use OPTIONS/REGISTER','REGISTER']),  		
			Opt::RPORT(5060),
			Opt::CPORT(5060)
		], self.class)		
	end


	# Define our batch size
	def run_batch_size
		datastore['BATCHSIZE'].to_i
	end
	
	# Operate on an entire batch of hosts at once
	def run_batch(batch)

		begin		
			udp_sock = nil
			idx = 0
			
			# Create an unbound UDP socket
			udp_sock = Rex::Socket::Udp.create('LocalPort' => datastore['CPORT'].to_i)

			mini = datastore['MINEXT']
			maxi = datastore['MAXEXT']
				
			batch.each do |ip|
				for i in (mini..maxi)
					testext = padnum(i,datastore['PADLEN'])
					
					case datastore['METHOD']
					when 'REGISTER'
						data = create_probe(ip,testext,'REGISTER')
					when 'OPTIONS'	
						data = create_probe(ip,testext,'OPTIONS')
					else
						print_error("Method not found.")
						return	
					end
							

					begin
						udp_sock.sendto(data, ip, datastore['RPORT'].to_i, 0)
					rescue ::Interrupt
						raise $!
					rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
						nil
					end

					if (idx % 10 == 0)
						while (r = udp_sock.recvfrom(65535, 0.01) and r[1])
							parse_reply(r,datastore['METHOD'])
						end
					end

					idx += 1
				end
			end

			while (r = udp_sock.recvfrom(65535, 3) and r[1])
				parse_reply(r,datastore['METHOD'])
			end
			
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			print_status("Unknown error: #{e.class} #{e}")
		ensure
			udp_sock.close if udp_sock
		end
	end

	#
	# The response parsers
	#
	def parse_reply(pkt,meth)

		return if not pkt[1]
		
		if(pkt[1] =~ /^::ffff:/)
			pkt[1] = pkt[1].sub(/^::ffff:/, '')
		end

		resp  = pkt[0].split(/\s+/)[1]
		repcode = '' 
		agent = ''
		verbs = ''
		serv  = ''
		prox  = ''		
		
		if(pkt[0] =~ /^To\:\s*(.*)$/i)
			testn = "#{$1.strip}".split(';')[0]
		end
		
		case resp.to_i
		when 401 
			print_status("Found user: #{testn} [Auth]")
		when 200	
			print_status("Found user: #{testn} [Open]")
		else
			#print_error("Undefined error code: #{resp.to_i}"	
		end
	end

	def create_probe(ip,toext,meth)
		suser = Rex::Text.rand_text_alphanumeric(rand(8)+1)
		shost = Rex::Socket.source_address(ip)
		src   = "#{shost}:#{datastore['CPORT']}"

		data  = "#{meth} sip:#{toext}@#{ip} SIP/2.0\r\n"
		data << "Via: SIP/2.0/UDP #{src};branch=z9hG4bK.#{"%.8x" % rand(0x100000000)};rport;alias\r\n"
		data << "From: #{toext} <sip:#{suser}@#{src}>;tag=70c00e8c\r\n"
		data << "To: #{toext} <sip:#{toext}@#{ip}>\r\n"
		data << "Call-ID: #{rand(0x100000000)}@#{shost}\r\n"
		data << "CSeq: 1 #{meth}\r\n"
		data << "Contact: <sip:#{suser}@#{src}>\r\n"
		data << "Content-Length: 0\r\n"
		data << "Max-Forwards: 20\r\n"
		data << "User-Agent: #{suser}\r\n"
		data << "Accept: text/plain\r\n"
	end
	
	def padnum(num,padding)
		if padding >= num.to_s.length 
			('0'*(padding-num.to_s.length)) << num.to_s
		end	
	end		
end
