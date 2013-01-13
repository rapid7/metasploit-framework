##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core/exploit/tcp'

class Metasploit3 < Msf::Auxiliary

	include Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	@@cached_rsa_key = nil

	def initialize
		super(
			'Name'        => 'VMWare Authentication Daemon Version Scanner',
			'Description' => %q{
				This module will identify information about a host through the
			vmauthd service.
			},
			'Author'      => ['theLightCosine', 'hdm'],
			'License'     => MSF_LICENSE
		)

		register_options([Opt::RPORT(902)])

	end



	def run_host(ip)
		begin

		connect rescue nil
		if not self.sock
			return
		end

		banner = sock.get_once(-1, 10)
		if not banner
			print_error "#{rhost}:#{rport} No banner received from vmauthd"
			return
		end

		banner = banner.strip

		unless banner =~ /VMware Authentication Daemon/
			print_error "#{rhost}:#{rport} This does not appear to be a vmauthd service"
			return
		end

		cert = nil

		if banner =~ /SSL/
			print_status("#{rhost}:#{rport} Switching to SSL connection...")
			swap_sock_plain_to_ssl
			cert = self.sock.peer_cert
		end

		if cert
			banner << " Certificate:#{cert.subject.to_s}"
		end

		print_status "#{rhost}:#{rport} Banner: #{banner}"

		report_service(
			:host  => rhost,
			:port  => rport,
			:sname => 'vmauthd',
			:info  => banner,
			:proto => 'tcp'
		)


		rescue ::Interrupt
			raise $!
		ensure
			disconnect
		end

	end

	def do_login(user, pass, nsock=self.sock)
		nsock.put("USER #{user}\r\n")
		res = nsock.get_once
		unless res.start_with? "331"
			ret_msg = "Unexpected reply to the USER command: #{res}"
			return ret_msg
		end
		nsock.put("PASS #{pass}\r\n")
		res = nsock.get_once || ''
		if res.start_with? "530"
			return :failed
		elsif res.start_with? "230"
			return :success
		else
			ret_msg = "Unexpected reply to the PASS command: #{res}"
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
