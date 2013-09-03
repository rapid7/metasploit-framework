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
			'Name'        => 'SIP Endpoint Scanner (TCP)',
			'Description' => 'Scan for SIP devices using OPTIONS requests',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
			OptString.new('TO',   [ false, "The destination username to probe at each host", "nobody"]),
			Opt::RPORT(5060)
		], self.class)
	end

	# Operate on a single system at a time
	def run_host(ip)

		begin
			idx = 0

			connect
			sock.put(create_probe(ip))
			res = sock.get_once(-1, 5)
			parse_reply(res) if res

		rescue ::Interrupt
			raise $!
		ensure
			disconnect
		end
	end

	#
	# The response parser
	#
	def parse_reply(resp)

		rcode = resp.split(/\s+/)[0]
		agent = ''
		verbs = ''
		serv  = ''
		prox  = ''

		if(resp =~ /^User-Agent:\s*(.*)$/i)
			agent = "agent='#{$1.strip}' "
		end

		if(resp =~ /^Allow:\s+(.*)$/i)
			verbs = "verbs='#{$1.strip}' "
		end

		if(resp =~ /^Server:\s+(.*)$/)
			serv = "server='#{$1.strip}' "
		end

		if(resp =~ /^Proxy-Require:\s+(.*)$/)
			serv = "proxy-required='#{$1.strip}' "
		end

		print_status("#{rhost} #{rcode} #{agent}#{serv}#{prox}#{verbs}")

		report_service(
			:host   => rhost,
			:port   => rport,
			:proto  => 'tcp',
			:name   => 'sip'
		)

		if(not agent.empty?)
			report_note(
				:host   => rhost,
				:type  => 'sip_useragent',
				:data   => agent
			)
		end
	end

	def create_probe(ip)
		suser = Rex::Text.rand_text_alphanumeric(rand(8)+1)
		shost = Rex::Socket.source_address(ip)
		src   = "#{shost}:#{datastore['RPORT']}"

		data  = "OPTIONS sip:#{datastore['TO']}@#{ip} SIP/2.0\r\n"
		data << "Via: SIP/2.0/TCP #{src};branch=z9hG4bK.#{"%.8x" % rand(0x100000000)};rport;alias\r\n"
		data << "From: sip:#{suser}@#{src};tag=70c00e8c\r\n"
		data << "To: sip:#{datastore['TO']}@#{ip}\r\n"
		data << "Call-ID: #{rand(0x100000000)}@#{shost}\r\n"
		data << "CSeq: 1 OPTIONS\r\n"
		data << "Contact:  sip:#{suser}@#{src}\r\n"
		data << "Max-Forwards: 20\r\n"
		data << "User-Agent: #{suser}\r\n"
		data << "Accept: text/plain\r\n"
		data << "Content-Length: 0\r\n"
		data << "\r\n"
		data
	end


end
