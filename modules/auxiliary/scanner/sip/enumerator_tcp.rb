##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'SIP Username Enumerator (TCP)',
			'Description' => 'Scan for numeric username/extensions using OPTIONS/REGISTER requests',
			'Author'      => 'et',
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			OptInt.new('MINEXT',   [true, 'Starting extension',0]),
			OptInt.new('MAXEXT',   [true, 'Ending extension', 9999]),
			OptInt.new('PADLEN',   [true, 'Cero padding maximum length', 4]),
			OptEnum.new('METHOD',  [true, 'Enumeration method', 'REGISTER', ['OPTIONS', 'REGISTER']]),
			Opt::RPORT(5060)
		], self.class)
	end


	# Operate on a single system at a time
	def run_host(ip)

		connect

		begin
			idx  = 0
			mini = datastore['MINEXT']
			maxi = datastore['MAXEXT']

			for i in (mini..maxi)
				testext = padnum(i,datastore['PADLEN'])
				data    = ""

				case datastore['METHOD']
				when 'REGISTER'
					data = create_probe(ip,testext,'REGISTER')
				when 'OPTIONS'
					data = create_probe(ip,testext,'OPTIONS')
				end

				begin
					sock.put(data)
					res = sock.get_once(-1, 5)
					parse_reply(res,datastore['METHOD']) if res
				rescue ::Interrupt
					raise $!
				rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
					nil
				end
			end
		rescue ::EOFError
		rescue ::Interrupt
			raise $!
		ensure
			disconnect
		end
	end

	#
	# The response parsers
	#
	def parse_reply(resp,meth)

		repcode = ''
		agent  = ''
		verbs = ''
		serv  = ''
		prox  = ''

		if(resp =~ /^To\:\s*(.*)$/mi)
			testn = "#{$1.strip}".split(';')[0]
		end

		case resp
		when /^401/
			print_status("Found user: #{testn} [Auth]")
			#Add Report
			report_note(
				:host	=> rhost,
				:proto	=> 'sip',
				:port	=> rport,
				:type	=> "Found user: #{testn} [Auth]",
				:data	=> "Found user: #{testn} [Auth]"
			)
		when /^200/
			print_status("Found user: #{testn} [Open]")
			#Add Report
			report_note(
				:host	=> rhost,
				:proto	=> 'sip',
				:port	=> rport,
				:type	=> "Found user: #{testn} [Open]",
				:data	=> "Found user: #{testn} [Open]"
			)
		else
			#print_error("Undefined error code: #{resp.to_i}"
		end
	end

	def create_probe(ip,toext,meth)
		suser = Rex::Text.rand_text_alphanumeric(rand(8)+1)
		shost = Rex::Socket.source_address(ip)
		src   = "#{shost}:#{datastore['RPORT']}"

		data  = "#{meth} sip:#{toext}@#{ip} SIP/2.0\r\n"
		data << "Via: SIP/2.0/TCP #{src};branch=z9hG4bK.#{"%.8x" % rand(0x100000000)};rport;alias\r\n"
		data << "From: #{toext} <sip:#{suser}@#{src}>;tag=70c00e8c\r\n"
		data << "To: #{toext} <sip:#{toext}@#{ip}>\r\n"
		data << "Call-ID: #{rand(0x100000000)}@#{shost}\r\n"
		data << "CSeq: 1 #{meth}\r\n"
		data << "Contact: <sip:#{suser}@#{src}>\r\n"
		data << "Max-Forwards: 20\r\n"
		data << "User-Agent: #{suser}\r\n"
		data << "Accept: text/plain\r\n"
		data << "Content-Length: 0\r\n"
		data << "\r\n"
		data
	end

	def padnum(num,padding)
		if padding >= num.to_s.length
			('0'*(padding-num.to_s.length)) << num.to_s
		end
	end
end
